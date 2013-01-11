/******************************************************************************
 * mm/hypervisor.c
 * 
 * Update page tables via the hypervisor.
 * 
 * Copyright (c) 2002-2004, K A Fraser
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/hypervisor.h>
#include <xen/balloon.h>
#include <xen/features.h>
#include <xen/interface/memory.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <asm/tlbflush.h>
#include <linux/highmem.h>

void xen_l1_entry_update(pte_t *ptr, pte_t val)
{
	mmu_update_t u;
	u.ptr = ptep_to_machine(ptr);
	u.val = __pte_val(val);
	BUG_ON(HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF) < 0);
}
EXPORT_SYMBOL_GPL(xen_l1_entry_update);

void xen_l2_entry_update(pmd_t *ptr, pmd_t val)
{
	mmu_update_t u;
	u.ptr = virt_to_machine(ptr);
	u.val = __pmd_val(val);
	BUG_ON(HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF) < 0);
}

#if defined(CONFIG_X86_PAE) || defined(CONFIG_X86_64)
void xen_l3_entry_update(pud_t *ptr, pud_t val)
{
	mmu_update_t u;
	u.ptr = virt_to_machine(ptr);
	u.val = __pud_val(val);
	BUG_ON(HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF) < 0);
}
#endif

#ifdef CONFIG_X86_64
void xen_l4_entry_update(pgd_t *ptr, pgd_t val)
{
	mmu_update_t u;
	u.ptr = virt_to_machine(ptr);
	u.val = __pgd_val(val);
	BUG_ON(HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF) < 0);
}
#endif /* CONFIG_X86_64 */

void xen_pt_switch(unsigned long ptr)
{
	struct mmuext_op op;
	op.cmd = MMUEXT_NEW_BASEPTR;
	op.arg1.mfn = pfn_to_mfn(ptr >> PAGE_SHIFT);
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_new_user_pt(unsigned long ptr)
{
	struct mmuext_op op;
	op.cmd = MMUEXT_NEW_USER_BASEPTR;
	op.arg1.mfn = pfn_to_mfn(ptr >> PAGE_SHIFT);
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_tlb_flush(void)
{
	struct mmuext_op op;
	op.cmd = MMUEXT_TLB_FLUSH_LOCAL;
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}
EXPORT_SYMBOL(xen_tlb_flush);

void xen_invlpg(unsigned long ptr)
{
	struct mmuext_op op;
	op.cmd = MMUEXT_INVLPG_LOCAL;
	op.arg1.linear_addr = ptr & PAGE_MASK;
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}
EXPORT_SYMBOL(xen_invlpg);

#ifdef CONFIG_SMP

void xen_tlb_flush_all(void)
{
	struct mmuext_op op;
	op.cmd = MMUEXT_TLB_FLUSH_ALL;
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}
EXPORT_SYMBOL_GPL(xen_tlb_flush_all);

void xen_tlb_flush_mask(cpumask_t *mask)
{
	struct mmuext_op op;
	if ( cpus_empty(*mask) )
		return;
	op.cmd = MMUEXT_TLB_FLUSH_MULTI;
	set_xen_guest_handle(op.arg2.vcpumask, mask->bits);
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}
EXPORT_SYMBOL_GPL(xen_tlb_flush_mask);

void xen_invlpg_all(unsigned long ptr)
{
	struct mmuext_op op;
	op.cmd = MMUEXT_INVLPG_ALL;
	op.arg1.linear_addr = ptr & PAGE_MASK;
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}
EXPORT_SYMBOL_GPL(xen_invlpg_all);

void xen_invlpg_mask(cpumask_t *mask, unsigned long ptr)
{
	struct mmuext_op op;
	if ( cpus_empty(*mask) )
		return;
	op.cmd = MMUEXT_INVLPG_MULTI;
	op.arg1.linear_addr = ptr & PAGE_MASK;
	set_xen_guest_handle(op.arg2.vcpumask, mask->bits);
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}
EXPORT_SYMBOL_GPL(xen_invlpg_mask);

#endif /* CONFIG_SMP */

void xen_pgd_pin(unsigned long ptr)
{
	struct mmuext_op op;
#ifdef CONFIG_X86_64
	op.cmd = MMUEXT_PIN_L4_TABLE;
#elif defined(CONFIG_X86_PAE)
	op.cmd = MMUEXT_PIN_L3_TABLE;
#else
	op.cmd = MMUEXT_PIN_L2_TABLE;
#endif
	op.arg1.mfn = pfn_to_mfn(ptr >> PAGE_SHIFT);
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_pgd_unpin(unsigned long ptr)
{
	struct mmuext_op op;
	op.cmd = MMUEXT_UNPIN_TABLE;
	op.arg1.mfn = pfn_to_mfn(ptr >> PAGE_SHIFT);
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_set_ldt(const void *ptr, unsigned int ents)
{
	struct mmuext_op op;
	op.cmd = MMUEXT_SET_LDT;
	op.arg1.linear_addr = (unsigned long)ptr;
	op.arg2.nr_ents     = ents;
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

/* Protected by balloon_lock. */
#define INIT_CONTIG_ORDER 6 /* 256kB */
static unsigned int __read_mostly max_contig_order = INIT_CONTIG_ORDER;
static unsigned long __initdata init_df[1U << INIT_CONTIG_ORDER];
static unsigned long *__read_mostly discontig_frames = init_df;
static multicall_entry_t __initdata init_mc[1U << INIT_CONTIG_ORDER];
static multicall_entry_t *__read_mostly cr_mcl = init_mc;

static int __init init_contig_order(void)
{
	discontig_frames = vmalloc((sizeof(*discontig_frames)
				    + sizeof(*cr_mcl)) << INIT_CONTIG_ORDER);
	BUG_ON(!discontig_frames);

	cr_mcl = (void *)(discontig_frames + (1U << INIT_CONTIG_ORDER));

	return 0;
}
core_initcall(init_contig_order);

static int check_contig_order(unsigned int order)
{
#ifdef CONFIG_64BIT
	if (unlikely(order >= 32))
#else
	if (unlikely(order > BITS_PER_LONG - fls(sizeof(*cr_mcl))))
#endif
		return -ENOMEM;

	if (unlikely(order > max_contig_order))
	{
		unsigned long *df = __vmalloc((sizeof(*discontig_frames)
					       + sizeof(*cr_mcl)) << order,
					      GFP_ATOMIC, PAGE_KERNEL);
		unsigned long flags;

		if (!df) {
			vfree(df);
			return -ENOMEM;
		}
		balloon_lock(flags);
		if (order > max_contig_order) {
			void *temp = discontig_frames;

			discontig_frames = df;
			cr_mcl = (void *)(df + (1U << order));
			df = temp;

			wmb();
			max_contig_order = order;
		}
		balloon_unlock(flags);
		vfree(df);
		printk(KERN_INFO
		       "Adjusted maximum contiguous region order to %u\n",
		       order);
	}

	return 0;
}

/* Ensure multi-page extents are contiguous in machine memory. */
int xen_create_contiguous_region(
	unsigned long vstart, unsigned int order, unsigned int address_bits)
{
	unsigned long *in_frames, out_frame, frame, flags;
	unsigned int   i;
	int            rc, success;
	struct xen_memory_exchange exchange = {
		.in = {
			.nr_extents   = 1UL << order,
			.extent_order = 0,
			.domid        = DOMID_SELF
		},
		.out = {
			.nr_extents   = 1,
			.extent_order = order,
			.address_bits = address_bits,
			.domid        = DOMID_SELF
		}
	};

	/*
	 * Currently an auto-translated guest will not perform I/O, nor will
	 * it require PAE page directories below 4GB. Therefore any calls to
	 * this function are redundant and can be ignored.
	 */
	if (xen_feature(XENFEAT_auto_translated_physmap))
		return 0;

	rc = check_contig_order(order);
	if (unlikely(rc))
		return rc;

	set_xen_guest_handle(exchange.out.extent_start, &out_frame);

	scrub_pages((void *)vstart, 1 << order);

	balloon_lock(flags);

	in_frames = discontig_frames;
	set_xen_guest_handle(exchange.in.extent_start, in_frames);

	/* 1. Zap current PTEs, remembering MFNs. */
	for (i = 0; i < (1U<<order); i++) {
		in_frames[i] = pfn_to_mfn((__pa(vstart) >> PAGE_SHIFT) + i);
		MULTI_update_va_mapping(cr_mcl + i, vstart + (i*PAGE_SIZE),
					__pte_ma(0), 0);
		set_phys_to_machine((__pa(vstart)>>PAGE_SHIFT)+i,
			INVALID_P2M_ENTRY);
	}
	if (HYPERVISOR_multicall_check(cr_mcl, i, NULL))
		BUG();

	/* 2. Get a new contiguous memory extent. */
	out_frame = __pa(vstart) >> PAGE_SHIFT;
	rc = HYPERVISOR_memory_op(XENMEM_exchange, &exchange);
	success = (exchange.nr_exchanged == (1UL << order));
	BUG_ON(!success && ((exchange.nr_exchanged != 0) || (rc == 0)));
	BUG_ON(success && (rc != 0));
#if CONFIG_XEN_COMPAT <= 0x030002
	if (unlikely(rc == -ENOSYS)) {
		/* Compatibility when XENMEM_exchange is unsupported. */
		if (HYPERVISOR_memory_op(XENMEM_decrease_reservation,
					 &exchange.in) != (1UL << order))
			BUG();
		success = (HYPERVISOR_memory_op(XENMEM_populate_physmap,
						&exchange.out) == 1);
		if (!success) {
			/* Couldn't get special memory: fall back to normal. */
			for (i = 0; i < (1U<<order); i++)
				in_frames[i] = (__pa(vstart)>>PAGE_SHIFT) + i;
			if (HYPERVISOR_memory_op(XENMEM_populate_physmap,
						 &exchange.in) != (1UL<<order))
				BUG();
		}
	}
#endif

	/* 3. Map the new extent in place of old pages. */
	for (i = 0; i < (1U<<order); i++) {
		frame = success ? (out_frame + i) : in_frames[i];
		MULTI_update_va_mapping(cr_mcl + i, vstart + (i*PAGE_SIZE),
					pfn_pte_ma(frame, PAGE_KERNEL), 0);
		set_phys_to_machine((__pa(vstart)>>PAGE_SHIFT)+i, frame);
	}

	cr_mcl[i - 1].args[MULTI_UVMFLAGS_INDEX] = order
						   ? UVMF_TLB_FLUSH|UVMF_ALL
						   : UVMF_INVLPG|UVMF_ALL;
	if (HYPERVISOR_multicall_check(cr_mcl, i, NULL))
		BUG();

	balloon_unlock(flags);

	return success ? 0 : -ENOMEM;
}
EXPORT_SYMBOL_GPL(xen_create_contiguous_region);

void xen_destroy_contiguous_region(unsigned long vstart, unsigned int order)
{
	unsigned long *out_frames, in_frame, frame, flags;
	unsigned int   i;
	int            rc, success;
	struct xen_memory_exchange exchange = {
		.in = {
			.nr_extents   = 1,
			.extent_order = order,
			.domid        = DOMID_SELF
		},
		.out = {
			.nr_extents   = 1UL << order,
			.extent_order = 0,
			.domid        = DOMID_SELF
		}
	};

	if (xen_feature(XENFEAT_auto_translated_physmap))
		return;

	if (unlikely(order > max_contig_order))
		return;

	set_xen_guest_handle(exchange.in.extent_start, &in_frame);

	scrub_pages((void *)vstart, 1 << order);

	balloon_lock(flags);

	out_frames = discontig_frames;
	set_xen_guest_handle(exchange.out.extent_start, out_frames);

	/* 1. Find start MFN of contiguous extent. */
	in_frame = pfn_to_mfn(__pa(vstart) >> PAGE_SHIFT);

	/* 2. Zap current PTEs. */
	for (i = 0; i < (1U<<order); i++) {
		MULTI_update_va_mapping(cr_mcl + i, vstart + (i*PAGE_SIZE),
					__pte_ma(0), 0);
		set_phys_to_machine((__pa(vstart)>>PAGE_SHIFT)+i,
			INVALID_P2M_ENTRY);
		out_frames[i] = (__pa(vstart) >> PAGE_SHIFT) + i;
	}
	if (HYPERVISOR_multicall_check(cr_mcl, i, NULL))
		BUG();

	/* 3. Do the exchange for non-contiguous MFNs. */
	rc = HYPERVISOR_memory_op(XENMEM_exchange, &exchange);
	success = (exchange.nr_exchanged == 1);
	BUG_ON(!success && ((exchange.nr_exchanged != 0) || (rc == 0)));
	BUG_ON(success && (rc != 0));
#if CONFIG_XEN_COMPAT <= 0x030002
	if (unlikely(rc == -ENOSYS)) {
		/* Compatibility when XENMEM_exchange is unsupported. */
		if (HYPERVISOR_memory_op(XENMEM_decrease_reservation,
					 &exchange.in) != 1)
			BUG();
		if (HYPERVISOR_memory_op(XENMEM_populate_physmap,
					 &exchange.out) != (1UL << order))
			BUG();
		success = 1;
	}
#endif

	/* 4. Map new pages in place of old pages. */
	for (i = 0; i < (1U<<order); i++) {
		frame = success ? out_frames[i] : (in_frame + i);
		MULTI_update_va_mapping(cr_mcl + i, vstart + (i*PAGE_SIZE),
					pfn_pte_ma(frame, PAGE_KERNEL), 0);
		set_phys_to_machine((__pa(vstart)>>PAGE_SHIFT)+i, frame);
	}

	cr_mcl[i - 1].args[MULTI_UVMFLAGS_INDEX] = order
						   ? UVMF_TLB_FLUSH|UVMF_ALL
						   : UVMF_INVLPG|UVMF_ALL;
	if (HYPERVISOR_multicall_check(cr_mcl, i, NULL))
		BUG();

	balloon_unlock(flags);
}
EXPORT_SYMBOL_GPL(xen_destroy_contiguous_region);

static void undo_limit_pages(struct page *pages, unsigned int order)
{
	BUG_ON(xen_feature(XENFEAT_auto_translated_physmap));
	BUG_ON(order > max_contig_order);
	xen_limit_pages_to_max_mfn(pages, order, 0);
	ClearPageForeign(pages);
	__free_pages(pages, order);
}

int xen_limit_pages_to_max_mfn(
	struct page *pages, unsigned int order, unsigned int address_bits)
{
	unsigned long flags, frame, *limit_map, _limit_map;
	unsigned long *in_frames, *out_frames;
	struct page *page;
	unsigned int i, n, nr_mcl;
	int rc, success;

	struct xen_memory_exchange exchange = {
		.in = {
			.extent_order = 0,
			.domid        = DOMID_SELF
		},
		.out = {
			.extent_order = 0,
			.address_bits = address_bits,
			.domid        = DOMID_SELF
		}
	};

	if (xen_feature(XENFEAT_auto_translated_physmap))
		return 0;

	if (address_bits && address_bits < PAGE_SHIFT)
		return -EINVAL;

	rc = check_contig_order(order + 1);
	if (unlikely(rc))
		return rc;

	if (BITS_PER_LONG >> order) {
		limit_map = kmalloc(BITS_TO_LONGS(1U << order)
				    * sizeof(*limit_map), GFP_ATOMIC);
		if (unlikely(!limit_map))
			return -ENOMEM;
	} else
		limit_map = &_limit_map;

	if (address_bits)
		bitmap_zero(limit_map, 1U << order);
	else if (order) {
		BUILD_BUG_ON(sizeof(pages->index) != sizeof(*limit_map));
		for (i = 0; i < BITS_TO_LONGS(1U << order); ++i)
			limit_map[i] = pages[i + 1].index;
	} else
		__set_bit(0, limit_map);

	/* 0. Scrub the pages. */
	for (i = 0, n = 0; i < 1U<<order ; i++) {
		page = &pages[i];
		if (address_bits) {
			if (!(pfn_to_mfn(page_to_pfn(page)) >> (address_bits - PAGE_SHIFT)))
				continue;
			__set_bit(i, limit_map);
		}

		if (!PageHighMem(page))
			scrub_pages(page_address(page), 1);
#ifdef CONFIG_XEN_SCRUB_PAGES
		else {
			scrub_pages(kmap(page), 1);
			kunmap(page);
			++n;
		}
#endif
	}
	if (bitmap_empty(limit_map, 1U << order)) {
		if (limit_map != &_limit_map)
			kfree(limit_map);
		return 0;
	}

	if (n)
		kmap_flush_unused();

	balloon_lock(flags);

	in_frames = discontig_frames;
	set_xen_guest_handle(exchange.in.extent_start, in_frames);
	out_frames = in_frames + (1U << order);
	set_xen_guest_handle(exchange.out.extent_start, out_frames);

	/* 1. Zap current PTEs (if any), remembering MFNs. */
	for (i = 0, n = 0, nr_mcl = 0; i < (1U<<order); i++) {
		if(!test_bit(i, limit_map))
			continue;
		page = &pages[i];

		out_frames[n] = page_to_pfn(page);
		in_frames[n] = pfn_to_mfn(out_frames[n]);

		if (!PageHighMem(page))
			MULTI_update_va_mapping(cr_mcl + nr_mcl++,
						(unsigned long)page_address(page),
						__pte_ma(0), 0);

		set_phys_to_machine(out_frames[n], INVALID_P2M_ENTRY);
		++n;
	}
	if (nr_mcl && HYPERVISOR_multicall_check(cr_mcl, nr_mcl, NULL))
		BUG();

	/* 2. Get new memory below the required limit. */
	exchange.in.nr_extents = n;
	exchange.out.nr_extents = n;
	rc = HYPERVISOR_memory_op(XENMEM_exchange, &exchange);
	success = (exchange.nr_exchanged == n);
	BUG_ON(!success && ((exchange.nr_exchanged != 0) || (rc == 0)));
	BUG_ON(success && (rc != 0));
#if CONFIG_XEN_COMPAT <= 0x030002
	if (unlikely(rc == -ENOSYS)) {
		/* Compatibility when XENMEM_exchange is unsupported. */
		if (HYPERVISOR_memory_op(XENMEM_decrease_reservation,
					 &exchange.in) != n)
			BUG();
		if (HYPERVISOR_memory_op(XENMEM_populate_physmap,
					 &exchange.out) != n)
			BUG();
		success = 1;
	}
#endif

	/* 3. Map the new pages in place of old pages. */
	for (i = 0, n = 0, nr_mcl = 0; i < (1U<<order); i++) {
		if(!test_bit(i, limit_map))
			continue;
		page = &pages[i];

		frame = success ? out_frames[n] : in_frames[n];

		if (!PageHighMem(page))
			MULTI_update_va_mapping(cr_mcl + nr_mcl++,
						(unsigned long)page_address(page),
						pfn_pte_ma(frame, PAGE_KERNEL), 0);

		set_phys_to_machine(page_to_pfn(page), frame);
		++n;
	}
	if (nr_mcl) {
		cr_mcl[nr_mcl - 1].args[MULTI_UVMFLAGS_INDEX] = order
							        ? UVMF_TLB_FLUSH|UVMF_ALL
							        : UVMF_INVLPG|UVMF_ALL;
		if (HYPERVISOR_multicall_check(cr_mcl, nr_mcl, NULL))
			BUG();
	}

	balloon_unlock(flags);

	if (success && address_bits) {
		if (order) {
			BUILD_BUG_ON(sizeof(*limit_map) != sizeof(pages->index));
			for (i = 0; i < BITS_TO_LONGS(1U << order); ++i)
				pages[i + 1].index = limit_map[i];
		}
		SetPageForeign(pages, undo_limit_pages);
	}

	if (limit_map != &_limit_map)
		kfree(limit_map);

	return success ? 0 : -ENOMEM;
}
EXPORT_SYMBOL_GPL(xen_limit_pages_to_max_mfn);

#ifdef __i386__
int write_ldt_entry(void *ldt, int entry, __u32 entry_a, __u32 entry_b)
{
	__u32 *lp = (__u32 *)((char *)ldt + entry * 8);
	maddr_t mach_lp = arbitrary_virt_to_machine(lp);
	return HYPERVISOR_update_descriptor(
		mach_lp, (u64)entry_a | ((u64)entry_b<<32));
}
#endif

#define MAX_BATCHED_FULL_PTES 32

int xen_change_pte_range(struct mm_struct *mm, pmd_t *pmd,
			 unsigned long addr, unsigned long end, pgprot_t newprot)
{
	int rc = 0, i = 0;
	mmu_update_t u[MAX_BATCHED_FULL_PTES];
	pte_t *pte;
	spinlock_t *ptl;

	if (!xen_feature(XENFEAT_mmu_pt_update_preserve_ad))
		return 0;

	pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
	do {
		if (pte_present(*pte)) {
			u[i].ptr = (__pmd_val(*pmd) & PHYSICAL_PAGE_MASK)
				   | ((unsigned long)pte & ~PAGE_MASK)
				   | MMU_PT_UPDATE_PRESERVE_AD;
			u[i].val = __pte_val(pte_modify(*pte, newprot));
			if (++i == MAX_BATCHED_FULL_PTES) {
				if ((rc = HYPERVISOR_mmu_update(
					&u[0], i, NULL, DOMID_SELF)) != 0)
					break;
				i = 0;
			}
		}
	} while (pte++, addr += PAGE_SIZE, addr != end);
	if (i)
		rc = HYPERVISOR_mmu_update( &u[0], i, NULL, DOMID_SELF);
	pte_unmap_unlock(pte - 1, ptl);
	BUG_ON(rc && rc != -ENOSYS);
	return !rc;
}
