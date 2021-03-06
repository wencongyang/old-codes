/*
 * Dynamic DMA mapping support.
 *
 * This implementation is a fallback for platforms that do not support
 * I/O TLBs (aka DMA address translation hardware).
 * Copyright (C) 2000 Asit Mallick <Asit.K.Mallick@intel.com>
 * Copyright (C) 2000 Goutham Rao <goutham.rao@intel.com>
 * Copyright (C) 2000, 2003 Hewlett-Packard Co
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 * Copyright (C) 2005 Keir Fraser <keir@xensource.com>
 */

#include <linux/cache.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/init.h>
#include <linux/bootmem.h>
#include <linux/highmem.h>
#include <asm/io.h>
#include <asm/pci.h>
#include <asm/dma.h>
#include <asm/uaccess.h>
#include <xen/gnttab.h>
#include <xen/interface/memory.h>
#include <asm-i386/mach-xen/asm/gnttab_dma.h>

int swiotlb;
EXPORT_SYMBOL(swiotlb);

#define OFFSET(val,align) ((unsigned long)((val) & ( (align) - 1)))

/*
 * Maximum allowable number of contiguous slabs to map,
 * must be a power of 2.  What is the appropriate value ?
 * The complexity of {map,unmap}_single is linearly dependent on this value.
 */
#define IO_TLB_SEGSIZE	128

/*
 * log of the size of each IO TLB slab.  The number of slabs is command line
 * controllable.
 */
#define IO_TLB_SHIFT 11

/*
 * Enumeration for sync targets
 */
enum dma_sync_target {
	SYNC_FOR_CPU = 0,
	SYNC_FOR_DEVICE = 1,
};

int swiotlb_force;

static char *iotlb_virt_start;
static unsigned long iotlb_nslabs;

/*
 * Used to do a quick range check in swiotlb_unmap_single and
 * swiotlb_sync_single_*, to see if the memory was in fact allocated by this
 * API.
 */
static unsigned long iotlb_pfn_start, iotlb_pfn_end;

/* Does the given dma address reside within the swiotlb aperture? */
static inline int in_swiotlb_aperture(dma_addr_t dev_addr)
{
	unsigned long pfn = mfn_to_local_pfn(dev_addr >> PAGE_SHIFT);
	return (pfn_valid(pfn)
		&& (pfn >= iotlb_pfn_start)
		&& (pfn < iotlb_pfn_end));
}

/*
 * When the IOMMU overflows we return a fallback buffer. This sets the size.
 */
static unsigned long io_tlb_overflow = 32*1024;

void *io_tlb_overflow_buffer;

/*
 * This is a free list describing the number of free entries available from
 * each index
 */
static unsigned int *io_tlb_list;
static unsigned int io_tlb_index;

/*
 * We need to save away the original address corresponding to a mapped entry
 * for the sync operations.
 */
static struct phys_addr {
	struct page *page;
	unsigned int offset;
} *io_tlb_orig_addr;

/*
 * Protect the above data structures in the map and unmap calls
 */
static DEFINE_SPINLOCK(io_tlb_lock);

static unsigned int dma_bits;
static unsigned int __initdata max_dma_bits = 32;
static int __init
setup_dma_bits(char *str)
{
	max_dma_bits = simple_strtoul(str, NULL, 0);
	return 0;
}
__setup("dma_bits=", setup_dma_bits);

static int __init
setup_io_tlb_npages(char *str)
{
	/* Unlike ia64, the size is aperture in megabytes, not 'slabs'! */
	if (isdigit(*str)) {
		iotlb_nslabs = simple_strtoul(str, &str, 0) <<
			(20 - IO_TLB_SHIFT);
		iotlb_nslabs = ALIGN(iotlb_nslabs, IO_TLB_SEGSIZE);
	}
	if (*str == ',')
		++str;
	/*
         * NB. 'force' enables the swiotlb, but doesn't force its use for
         * every DMA like it does on native Linux. 'off' forcibly disables
         * use of the swiotlb.
         */
	if (!strcmp(str, "force"))
		swiotlb_force = 1;
	else if (!strcmp(str, "off"))
		swiotlb_force = -1;
	return 1;
}
__setup("swiotlb=", setup_io_tlb_npages);
/* make io_tlb_overflow tunable too? */

/*
 * Statically reserve bounce buffer space and initialize bounce buffer data
 * structures for the software IO TLB used to implement the PCI DMA API.
 */
void
swiotlb_init_with_default_size (size_t default_size)
{
	unsigned long i, bytes;
	int rc;

	if (!iotlb_nslabs) {
		iotlb_nslabs = (default_size >> IO_TLB_SHIFT);
		iotlb_nslabs = ALIGN(iotlb_nslabs, IO_TLB_SEGSIZE);
	}

	bytes = iotlb_nslabs * (1UL << IO_TLB_SHIFT);

	/*
	 * Get IO TLB memory from the low pages
	 */
	iotlb_virt_start = alloc_bootmem_pages(bytes);
	if (!iotlb_virt_start)
		panic("Cannot allocate SWIOTLB buffer!\n");

	dma_bits = get_order(IO_TLB_SEGSIZE << IO_TLB_SHIFT) + PAGE_SHIFT;
	for (i = 0; i < iotlb_nslabs; i += IO_TLB_SEGSIZE) {
		do {
			rc = xen_create_contiguous_region(
				(unsigned long)iotlb_virt_start + (i << IO_TLB_SHIFT),
				get_order(IO_TLB_SEGSIZE << IO_TLB_SHIFT),
				dma_bits);
		} while (rc && dma_bits++ < max_dma_bits);
		if (rc) {
			if (i == 0)
				panic("No suitable physical memory available for SWIOTLB buffer!\n"
				      "Use dom0_mem Xen boot parameter to reserve\n"
				      "some DMA memory (e.g., dom0_mem=-128M).\n");
			iotlb_nslabs = i;
			i <<= IO_TLB_SHIFT;
			free_bootmem(__pa(iotlb_virt_start + i), bytes - i);
			bytes = i;
			for (dma_bits = 0; i > 0; i -= IO_TLB_SEGSIZE << IO_TLB_SHIFT) {
				unsigned int bits = fls64(virt_to_bus(iotlb_virt_start + i - 1));

				if (bits > dma_bits)
					dma_bits = bits;
			}
			break;
		}
	}

	/*
	 * Allocate and initialize the free list array.  This array is used
	 * to find contiguous free memory regions of size up to IO_TLB_SEGSIZE.
	 */
	io_tlb_list = alloc_bootmem(iotlb_nslabs * sizeof(int));
	for (i = 0; i < iotlb_nslabs; i++)
 		io_tlb_list[i] = IO_TLB_SEGSIZE - OFFSET(i, IO_TLB_SEGSIZE);
	io_tlb_index = 0;
	io_tlb_orig_addr = alloc_bootmem(
		iotlb_nslabs * sizeof(*io_tlb_orig_addr));

	/*
	 * Get the overflow emergency buffer
	 */
	io_tlb_overflow_buffer = alloc_bootmem(io_tlb_overflow);
	if (!io_tlb_overflow_buffer)
		panic("Cannot allocate SWIOTLB overflow buffer!\n");

	do {
		rc = xen_create_contiguous_region(
			(unsigned long)io_tlb_overflow_buffer,
			get_order(io_tlb_overflow),
			dma_bits);
	} while (rc && dma_bits++ < max_dma_bits);
	if (rc)
		panic("No suitable physical memory available for SWIOTLB overflow buffer!\n");

	iotlb_pfn_start = __pa(iotlb_virt_start) >> PAGE_SHIFT;
	iotlb_pfn_end   = iotlb_pfn_start + (bytes >> PAGE_SHIFT);

	printk(KERN_INFO "Software IO TLB enabled: \n"
	       " Aperture:     %lu megabytes\n"
	       " Kernel range: %p - %p\n"
	       " Address size: %u bits\n",
	       bytes >> 20,
	       iotlb_virt_start, iotlb_virt_start + bytes,
	       dma_bits);
}

void
swiotlb_init(void)
{
	long ram_end;
	size_t defsz = 64 * (1 << 20); /* 64MB default size */

	if (swiotlb_force == 1) {
		swiotlb = 1;
	} else if ((swiotlb_force != -1) &&
		   is_running_on_xen() &&
		   is_initial_xendomain()) {
		/* Domain 0 always has a swiotlb. */
		ram_end = HYPERVISOR_memory_op(XENMEM_maximum_ram_page, NULL);
		if (ram_end <= 0x7ffff)
			defsz = 2 * (1 << 20); /* 2MB on <2GB on systems. */
		swiotlb = 1;
	}

	if (swiotlb)
		swiotlb_init_with_default_size(defsz);
	else
		printk(KERN_INFO "Software IO TLB disabled\n");
}

/*
 * We use __copy_to_user_inatomic to transfer to the host buffer because the
 * buffer may be mapped read-only (e.g, in blkback driver) but lower-level
 * drivers map the buffer for DMA_BIDIRECTIONAL access. This causes an
 * unnecessary copy from the aperture to the host buffer, and a page fault.
 */
static void
__sync_single(struct phys_addr buffer, char *dma_addr, size_t size, int dir)
{
	if (PageHighMem(buffer.page)) {
		size_t len, bytes;
		char *dev, *host, *kmp;
		len = size;
		while (len != 0) {
			unsigned long flags;

			if (((bytes = len) + buffer.offset) > PAGE_SIZE)
				bytes = PAGE_SIZE - buffer.offset;
			local_irq_save(flags); /* protects KM_BOUNCE_READ */
			kmp  = kmap_atomic(buffer.page, KM_BOUNCE_READ);
			dev  = dma_addr + size - len;
			host = kmp + buffer.offset;
			if (dir == DMA_FROM_DEVICE) {
				if (__copy_to_user_inatomic(host, dev, bytes))
					/* inaccessible */;
			} else
				memcpy(dev, host, bytes);
			kunmap_atomic(kmp, KM_BOUNCE_READ);
			local_irq_restore(flags);
			len -= bytes;
			buffer.page++;
			buffer.offset = 0;
		}
	} else {
		char *host = (char *)phys_to_virt(
			page_to_pseudophys(buffer.page)) + buffer.offset;
		if (dir == DMA_FROM_DEVICE) {
			if (__copy_to_user_inatomic(host, dma_addr, size))
				/* inaccessible */;
		} else if (dir == DMA_TO_DEVICE)
			memcpy(dma_addr, host, size);
	}
}

/*
 * Allocates bounce buffer and returns its kernel virtual address.
 */
static void *
map_single(struct device *hwdev, struct phys_addr buffer, size_t size, int dir)
{
	unsigned long flags;
	char *dma_addr;
	unsigned int nslots, stride, index, wrap;
	struct phys_addr slot_buf;
	int i;

	/*
	 * For mappings greater than a page, we limit the stride (and
	 * hence alignment) to a page size.
	 */
	nslots = ALIGN(size, 1 << IO_TLB_SHIFT) >> IO_TLB_SHIFT;
	if (size > PAGE_SIZE)
		stride = (1 << (PAGE_SHIFT - IO_TLB_SHIFT));
	else
		stride = 1;

	BUG_ON(!nslots);

	/*
	 * Find suitable number of IO TLB entries size that will fit this
	 * request and allocate a buffer from that IO TLB pool.
	 */
	spin_lock_irqsave(&io_tlb_lock, flags);
	{
		wrap = index = ALIGN(io_tlb_index, stride);

		if (index >= iotlb_nslabs)
			wrap = index = 0;

		do {
			/*
			 * If we find a slot that indicates we have 'nslots'
			 * number of contiguous buffers, we allocate the
			 * buffers from that slot and mark the entries as '0'
			 * indicating unavailable.
			 */
			if (io_tlb_list[index] >= nslots) {
				int count = 0;

				for (i = index; i < (int)(index + nslots); i++)
					io_tlb_list[i] = 0;
				for (i = index - 1;
				     (OFFSET(i, IO_TLB_SEGSIZE) !=
				      IO_TLB_SEGSIZE -1) && io_tlb_list[i];
				     i--)
					io_tlb_list[i] = ++count;
				dma_addr = iotlb_virt_start +
					(index << IO_TLB_SHIFT);

				/*
				 * Update the indices to avoid searching in
				 * the next round.
				 */
				io_tlb_index = 
					((index + nslots) < iotlb_nslabs
					 ? (index + nslots) : 0);

				goto found;
			}
			index += stride;
			if (index >= iotlb_nslabs)
				index = 0;
		} while (index != wrap);

		spin_unlock_irqrestore(&io_tlb_lock, flags);
		return NULL;
	}
  found:
	spin_unlock_irqrestore(&io_tlb_lock, flags);

	/*
	 * Save away the mapping from the original address to the DMA address.
	 * This is needed when we sync the memory.  Then we sync the buffer if
	 * needed.
	 */
	slot_buf = buffer;
	for (i = 0; i < nslots; i++) {
		slot_buf.page += slot_buf.offset >> PAGE_SHIFT;
		slot_buf.offset &= PAGE_SIZE - 1;
		io_tlb_orig_addr[index+i] = slot_buf;
		slot_buf.offset += 1 << IO_TLB_SHIFT;
	}
	if ((dir == DMA_TO_DEVICE) || (dir == DMA_BIDIRECTIONAL))
		__sync_single(buffer, dma_addr, size, DMA_TO_DEVICE);

	return dma_addr;
}

static struct phys_addr dma_addr_to_phys_addr(char *dma_addr)
{
	int index = (dma_addr - iotlb_virt_start) >> IO_TLB_SHIFT;
	struct phys_addr buffer = io_tlb_orig_addr[index];
	buffer.offset += (long)dma_addr & ((1 << IO_TLB_SHIFT) - 1);
	buffer.page += buffer.offset >> PAGE_SHIFT;
	buffer.offset &= PAGE_SIZE - 1;
	return buffer;
}

/*
 * dma_addr is the kernel virtual address of the bounce buffer to unmap.
 */
static void
unmap_single(struct device *hwdev, char *dma_addr, size_t size, int dir)
{
	unsigned long flags;
	int i, count, nslots = ALIGN(size, 1 << IO_TLB_SHIFT) >> IO_TLB_SHIFT;
	int index = (dma_addr - iotlb_virt_start) >> IO_TLB_SHIFT;
	struct phys_addr buffer = dma_addr_to_phys_addr(dma_addr);

	/*
	 * First, sync the memory before unmapping the entry
	 */
	if ((dir == DMA_FROM_DEVICE) || (dir == DMA_BIDIRECTIONAL))
		__sync_single(buffer, dma_addr, size, DMA_FROM_DEVICE);

	/*
	 * Return the buffer to the free list by setting the corresponding
	 * entries to indicate the number of contigous entries available.
	 * While returning the entries to the free list, we merge the entries
	 * with slots below and above the pool being returned.
	 */
	spin_lock_irqsave(&io_tlb_lock, flags);
	{
		count = ((index + nslots) < ALIGN(index + 1, IO_TLB_SEGSIZE) ?
			 io_tlb_list[index + nslots] : 0);
		/*
		 * Step 1: return the slots to the free list, merging the
		 * slots with superceeding slots
		 */
		for (i = index + nslots - 1; i >= index; i--)
			io_tlb_list[i] = ++count;
		/*
		 * Step 2: merge the returned slots with the preceding slots,
		 * if available (non zero)
		 */
		for (i = index - 1;
		     (OFFSET(i, IO_TLB_SEGSIZE) !=
		      IO_TLB_SEGSIZE -1) && io_tlb_list[i];
		     i--)
			io_tlb_list[i] = ++count;
	}
	spin_unlock_irqrestore(&io_tlb_lock, flags);
}

static void
sync_single(struct device *hwdev, char *dma_addr, size_t size,
	    int dir, int target)
{
	struct phys_addr buffer = dma_addr_to_phys_addr(dma_addr);
	switch (target) {
	case SYNC_FOR_CPU:
		if (likely(dir == DMA_FROM_DEVICE || dir == DMA_BIDIRECTIONAL))
			__sync_single(buffer, dma_addr, size, DMA_FROM_DEVICE);
		else
			BUG_ON(dir != DMA_TO_DEVICE);
		break;
	case SYNC_FOR_DEVICE:
		if (likely(dir == DMA_TO_DEVICE || dir == DMA_BIDIRECTIONAL))
			__sync_single(buffer, dma_addr, size, DMA_TO_DEVICE);
		else
			BUG_ON(dir != DMA_FROM_DEVICE);
		break;
	default:
		BUG();
	}
}

static void
swiotlb_full(struct device *dev, size_t size, int dir, int do_panic)
{
	/*
	 * Ran out of IOMMU space for this operation. This is very bad.
	 * Unfortunately the drivers cannot handle this operation properly.
	 * unless they check for pci_dma_mapping_error (most don't)
	 * When the mapping is small enough return a static buffer to limit
	 * the damage, or panic when the transfer is too big.
	 */
	printk(KERN_ERR "PCI-DMA: Out of SW-IOMMU space for %lu bytes at "
	       "device %s\n", (unsigned long)size, dev ? dev->bus_id : "?");

	if (size > io_tlb_overflow && do_panic) {
		if (dir == PCI_DMA_FROMDEVICE || dir == PCI_DMA_BIDIRECTIONAL)
			panic("PCI-DMA: Memory would be corrupted\n");
		if (dir == PCI_DMA_TODEVICE || dir == PCI_DMA_BIDIRECTIONAL)
			panic("PCI-DMA: Random memory would be DMAed\n");
	}
}

/*
 * Map a single buffer of the indicated size for DMA in streaming mode.  The
 * PCI address to use is returned.
 *
 * Once the device is given the dma address, the device owns this memory until
 * either swiotlb_unmap_single or swiotlb_dma_sync_single is performed.
 */
dma_addr_t
swiotlb_map_single(struct device *hwdev, void *ptr, size_t size, int dir)
{
	dma_addr_t dev_addr = gnttab_dma_map_page(virt_to_page(ptr)) +
			      offset_in_page(ptr);
	void *map;
	struct phys_addr buffer;

	BUG_ON(dir == DMA_NONE);

	/*
	 * If the pointer passed in happens to be in the device's DMA window,
	 * we can safely return the device addr and not worry about bounce
	 * buffering it.
	 */
	if (!range_straddles_page_boundary(__pa(ptr), size) &&
	    !address_needs_mapping(hwdev, dev_addr))
		return dev_addr;

	/*
	 * Oh well, have to allocate and map a bounce buffer.
	 */
	gnttab_dma_unmap_page(dev_addr);
	buffer.page   = virt_to_page(ptr);
	buffer.offset = (unsigned long)ptr & ~PAGE_MASK;
	map = map_single(hwdev, buffer, size, dir);
	if (!map) {
		swiotlb_full(hwdev, size, dir, 1);
		map = io_tlb_overflow_buffer;
	}

	dev_addr = virt_to_bus(map);
	return dev_addr;
}

/*
 * Unmap a single streaming mode DMA translation.  The dma_addr and size must
 * match what was provided for in a previous swiotlb_map_single call.  All
 * other usages are undefined.
 *
 * After this call, reads by the cpu to the buffer are guaranteed to see
 * whatever the device wrote there.
 */
void
swiotlb_unmap_single(struct device *hwdev, dma_addr_t dev_addr, size_t size,
		     int dir)
{
	BUG_ON(dir == DMA_NONE);
	if (in_swiotlb_aperture(dev_addr))
		unmap_single(hwdev, bus_to_virt(dev_addr), size, dir);
	else
		gnttab_dma_unmap_page(dev_addr);
}

/*
 * Make physical memory consistent for a single streaming mode DMA translation
 * after a transfer.
 *
 * If you perform a swiotlb_map_single() but wish to interrogate the buffer
 * using the cpu, yet do not wish to teardown the PCI dma mapping, you must
 * call this function before doing so.  At the next point you give the PCI dma
 * address back to the card, you must first perform a
 * swiotlb_dma_sync_for_device, and then the device again owns the buffer
 */
static inline void
swiotlb_sync_single(struct device *hwdev, dma_addr_t dev_addr,
		    size_t size, int dir, int target)
{
	BUG_ON(dir == DMA_NONE);
	if (in_swiotlb_aperture(dev_addr))
		sync_single(hwdev, bus_to_virt(dev_addr), size, dir, target);
}

void
swiotlb_sync_single_for_cpu(struct device *hwdev, dma_addr_t dev_addr,
			    size_t size, int dir)
{
	swiotlb_sync_single(hwdev, dev_addr, size, dir, SYNC_FOR_CPU);
}

void
swiotlb_sync_single_for_device(struct device *hwdev, dma_addr_t dev_addr,
			       size_t size, int dir)
{
	swiotlb_sync_single(hwdev, dev_addr, size, dir, SYNC_FOR_DEVICE);
}

/*
 * Map a set of buffers described by scatterlist in streaming mode for DMA.
 * This is the scatter-gather version of the above swiotlb_map_single
 * interface.  Here the scatter gather list elements are each tagged with the
 * appropriate dma address and length.  They are obtained via
 * sg_dma_{address,length}(SG).
 *
 * NOTE: An implementation may be able to use a smaller number of
 *       DMA address/length pairs than there are SG table elements.
 *       (for example via virtual mapping capabilities)
 *       The routine returns the number of addr/length pairs actually
 *       used, at most nents.
 *
 * Device ownership issues as mentioned above for swiotlb_map_single are the
 * same here.
 */
int
swiotlb_map_sg(struct device *hwdev, struct scatterlist *sg, int nelems,
	       int dir)
{
	struct phys_addr buffer;
	dma_addr_t dev_addr;
	char *map;
	int i;

	BUG_ON(dir == DMA_NONE);

	for (i = 0; i < nelems; i++, sg++) {
		dev_addr = gnttab_dma_map_page(sg->page) + sg->offset;

		if (range_straddles_page_boundary(page_to_pseudophys(sg->page)
						  + sg->offset, sg->length)
		    || address_needs_mapping(hwdev, dev_addr)) {
			gnttab_dma_unmap_page(dev_addr);
			buffer.page   = sg->page;
			buffer.offset = sg->offset;
			map = map_single(hwdev, buffer, sg->length, dir);
			if (!map) {
				/* Don't panic here, we expect map_sg users
				   to do proper error handling. */
				swiotlb_full(hwdev, sg->length, dir, 0);
				swiotlb_unmap_sg(hwdev, sg - i, i, dir);
				sg[0].dma_length = 0;
				return 0;
			}
			sg->dma_address = (dma_addr_t)virt_to_bus(map);
		} else
			sg->dma_address = dev_addr;
		sg->dma_length = sg->length;
	}
	return nelems;
}

/*
 * Unmap a set of streaming mode DMA translations.  Again, cpu read rules
 * concerning calls here are the same as for swiotlb_unmap_single() above.
 */
void
swiotlb_unmap_sg(struct device *hwdev, struct scatterlist *sg, int nelems,
		 int dir)
{
	int i;

	BUG_ON(dir == DMA_NONE);

	for (i = 0; i < nelems; i++, sg++)
		if (in_swiotlb_aperture(sg->dma_address))
			unmap_single(hwdev, 
				     (void *)bus_to_virt(sg->dma_address),
				     sg->dma_length, dir);
		else
			gnttab_dma_unmap_page(sg->dma_address);
}

/*
 * Make physical memory consistent for a set of streaming mode DMA translations
 * after a transfer.
 *
 * The same as swiotlb_sync_single_* but for a scatter-gather list, same rules
 * and usage.
 */
static inline void
swiotlb_sync_sg(struct device *hwdev, struct scatterlist *sg,
		int nelems, int dir, int target)
{
	int i;

	BUG_ON(dir == DMA_NONE);

	for (i = 0; i < nelems; i++, sg++)
		if (in_swiotlb_aperture(sg->dma_address))
			sync_single(hwdev, bus_to_virt(sg->dma_address),
				    sg->dma_length, dir, target);
}

void
swiotlb_sync_sg_for_cpu(struct device *hwdev, struct scatterlist *sg,
			int nelems, int dir)
{
	swiotlb_sync_sg(hwdev, sg, nelems, dir, SYNC_FOR_CPU);
}

void
swiotlb_sync_sg_for_device(struct device *hwdev, struct scatterlist *sg,
			   int nelems, int dir)
{
	swiotlb_sync_sg(hwdev, sg, nelems, dir, SYNC_FOR_DEVICE);
}

#ifdef CONFIG_HIGHMEM

dma_addr_t
swiotlb_map_page(struct device *hwdev, struct page *page,
		 unsigned long offset, size_t size,
		 enum dma_data_direction direction)
{
	struct phys_addr buffer;
	dma_addr_t dev_addr;
	char *map;

	dev_addr = gnttab_dma_map_page(page) + offset;
	if (address_needs_mapping(hwdev, dev_addr)) {
		gnttab_dma_unmap_page(dev_addr);
		buffer.page   = page;
		buffer.offset = offset;
		map = map_single(hwdev, buffer, size, direction);
		if (!map) {
			swiotlb_full(hwdev, size, direction, 1);
			map = io_tlb_overflow_buffer;
		}
		dev_addr = (dma_addr_t)virt_to_bus(map);
	}

	return dev_addr;
}

void
swiotlb_unmap_page(struct device *hwdev, dma_addr_t dma_address,
		   size_t size, enum dma_data_direction direction)
{
	BUG_ON(direction == DMA_NONE);
	if (in_swiotlb_aperture(dma_address))
		unmap_single(hwdev, bus_to_virt(dma_address), size, direction);
	else
		gnttab_dma_unmap_page(dma_address);
}

#endif

int
swiotlb_dma_mapping_error(dma_addr_t dma_addr)
{
	return (dma_addr == virt_to_bus(io_tlb_overflow_buffer));
}

/*
 * Return whether the given PCI device DMA address mask can be supported
 * properly.  For example, if your device can only drive the low 24-bits
 * during PCI bus mastering, then you would pass 0x00ffffff as the mask to
 * this function.
 */
int
swiotlb_dma_supported (struct device *hwdev, u64 mask)
{
	return (mask >= ((1UL << dma_bits) - 1));
}

EXPORT_SYMBOL(swiotlb_init);
EXPORT_SYMBOL(swiotlb_map_single);
EXPORT_SYMBOL(swiotlb_unmap_single);
EXPORT_SYMBOL(swiotlb_map_sg);
EXPORT_SYMBOL(swiotlb_unmap_sg);
EXPORT_SYMBOL(swiotlb_sync_single_for_cpu);
EXPORT_SYMBOL(swiotlb_sync_single_for_device);
EXPORT_SYMBOL(swiotlb_sync_sg_for_cpu);
EXPORT_SYMBOL(swiotlb_sync_sg_for_device);
EXPORT_SYMBOL(swiotlb_dma_mapping_error);
EXPORT_SYMBOL(swiotlb_dma_supported);
