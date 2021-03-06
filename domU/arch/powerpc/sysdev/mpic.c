/*
 *  arch/powerpc/kernel/mpic.c
 *
 *  Driver for interrupt controllers following the OpenPIC standard, the
 *  common implementation beeing IBM's MPIC. This driver also can deal
 *  with various broken implementations of this HW.
 *
 *  Copyright (C) 2004 Benjamin Herrenschmidt, IBM Corp.
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of this archive
 *  for more details.
 */

#undef DEBUG
#undef DEBUG_IPI
#undef DEBUG_IRQ
#undef DEBUG_LOW

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/bootmem.h>
#include <linux/spinlock.h>
#include <linux/pci.h>

#include <asm/ptrace.h>
#include <asm/signal.h>
#include <asm/io.h>
#include <asm/pgtable.h>
#include <asm/irq.h>
#include <asm/machdep.h>
#include <asm/mpic.h>
#include <asm/smp.h>

#ifdef DEBUG
#define DBG(fmt...) printk(fmt)
#else
#define DBG(fmt...)
#endif

static struct mpic *mpics;
static struct mpic *mpic_primary;
static DEFINE_SPINLOCK(mpic_lock);

#ifdef CONFIG_PPC32	/* XXX for now */
#ifdef CONFIG_IRQ_ALL_CPUS
#define distribute_irqs	(1)
#else
#define distribute_irqs	(0)
#endif
#endif

#ifdef CONFIG_MPIC_WEIRD
static u32 mpic_infos[][MPIC_IDX_END] = {
	[0] = {	/* Original OpenPIC compatible MPIC */
		MPIC_GREG_BASE,
		MPIC_GREG_FEATURE_0,
		MPIC_GREG_GLOBAL_CONF_0,
		MPIC_GREG_VENDOR_ID,
		MPIC_GREG_IPI_VECTOR_PRI_0,
		MPIC_GREG_IPI_STRIDE,
		MPIC_GREG_SPURIOUS,
		MPIC_GREG_TIMER_FREQ,

		MPIC_TIMER_BASE,
		MPIC_TIMER_STRIDE,
		MPIC_TIMER_CURRENT_CNT,
		MPIC_TIMER_BASE_CNT,
		MPIC_TIMER_VECTOR_PRI,
		MPIC_TIMER_DESTINATION,

		MPIC_CPU_BASE,
		MPIC_CPU_STRIDE,
		MPIC_CPU_IPI_DISPATCH_0,
		MPIC_CPU_IPI_DISPATCH_STRIDE,
		MPIC_CPU_CURRENT_TASK_PRI,
		MPIC_CPU_WHOAMI,
		MPIC_CPU_INTACK,
		MPIC_CPU_EOI,

		MPIC_IRQ_BASE,
		MPIC_IRQ_STRIDE,
		MPIC_IRQ_VECTOR_PRI,
		MPIC_VECPRI_VECTOR_MASK,
		MPIC_VECPRI_POLARITY_POSITIVE,
		MPIC_VECPRI_POLARITY_NEGATIVE,
		MPIC_VECPRI_SENSE_LEVEL,
		MPIC_VECPRI_SENSE_EDGE,
		MPIC_VECPRI_POLARITY_MASK,
		MPIC_VECPRI_SENSE_MASK,
		MPIC_IRQ_DESTINATION
	},
	[1] = {	/* Tsi108/109 PIC */
		TSI108_GREG_BASE,
		TSI108_GREG_FEATURE_0,
		TSI108_GREG_GLOBAL_CONF_0,
		TSI108_GREG_VENDOR_ID,
		TSI108_GREG_IPI_VECTOR_PRI_0,
		TSI108_GREG_IPI_STRIDE,
		TSI108_GREG_SPURIOUS,
		TSI108_GREG_TIMER_FREQ,

		TSI108_TIMER_BASE,
		TSI108_TIMER_STRIDE,
		TSI108_TIMER_CURRENT_CNT,
		TSI108_TIMER_BASE_CNT,
		TSI108_TIMER_VECTOR_PRI,
		TSI108_TIMER_DESTINATION,

		TSI108_CPU_BASE,
		TSI108_CPU_STRIDE,
		TSI108_CPU_IPI_DISPATCH_0,
		TSI108_CPU_IPI_DISPATCH_STRIDE,
		TSI108_CPU_CURRENT_TASK_PRI,
		TSI108_CPU_WHOAMI,
		TSI108_CPU_INTACK,
		TSI108_CPU_EOI,

		TSI108_IRQ_BASE,
		TSI108_IRQ_STRIDE,
		TSI108_IRQ_VECTOR_PRI,
		TSI108_VECPRI_VECTOR_MASK,
		TSI108_VECPRI_POLARITY_POSITIVE,
		TSI108_VECPRI_POLARITY_NEGATIVE,
		TSI108_VECPRI_SENSE_LEVEL,
		TSI108_VECPRI_SENSE_EDGE,
		TSI108_VECPRI_POLARITY_MASK,
		TSI108_VECPRI_SENSE_MASK,
		TSI108_IRQ_DESTINATION
	},
};

#define MPIC_INFO(name) mpic->hw_set[MPIC_IDX_##name]

#else /* CONFIG_MPIC_WEIRD */

#define MPIC_INFO(name) MPIC_##name

#endif /* CONFIG_MPIC_WEIRD */

/*
 * Register accessor functions
 */


static inline u32 _mpic_read(unsigned int be, volatile u32 __iomem *base,
			    unsigned int reg)
{
	if (be)
		return in_be32(base + (reg >> 2));
	else
		return in_le32(base + (reg >> 2));
}

static inline void _mpic_write(unsigned int be, volatile u32 __iomem *base,
			      unsigned int reg, u32 value)
{
	if (be)
		out_be32(base + (reg >> 2), value);
	else
		out_le32(base + (reg >> 2), value);
}

static inline u32 _mpic_ipi_read(struct mpic *mpic, unsigned int ipi)
{
	unsigned int be = (mpic->flags & MPIC_BIG_ENDIAN) != 0;
	unsigned int offset = MPIC_INFO(GREG_IPI_VECTOR_PRI_0) +
			      (ipi * MPIC_INFO(GREG_IPI_STRIDE));

	if (mpic->flags & MPIC_BROKEN_IPI)
		be = !be;
	return _mpic_read(be, mpic->gregs, offset);
}

static inline void _mpic_ipi_write(struct mpic *mpic, unsigned int ipi, u32 value)
{
	unsigned int offset = MPIC_INFO(GREG_IPI_VECTOR_PRI_0) +
			      (ipi * MPIC_INFO(GREG_IPI_STRIDE));

	_mpic_write(mpic->flags & MPIC_BIG_ENDIAN, mpic->gregs, offset, value);
}

static inline u32 _mpic_cpu_read(struct mpic *mpic, unsigned int reg)
{
	unsigned int cpu = 0;

	if (mpic->flags & MPIC_PRIMARY)
		cpu = hard_smp_processor_id();
	return _mpic_read(mpic->flags & MPIC_BIG_ENDIAN,
			  mpic->cpuregs[cpu], reg);
}

static inline void _mpic_cpu_write(struct mpic *mpic, unsigned int reg, u32 value)
{
	unsigned int cpu = 0;

	if (mpic->flags & MPIC_PRIMARY)
		cpu = hard_smp_processor_id();

	_mpic_write(mpic->flags & MPIC_BIG_ENDIAN, mpic->cpuregs[cpu], reg, value);
}

static inline u32 _mpic_irq_read(struct mpic *mpic, unsigned int src_no, unsigned int reg)
{
	unsigned int	isu = src_no >> mpic->isu_shift;
	unsigned int	idx = src_no & mpic->isu_mask;

	return _mpic_read(mpic->flags & MPIC_BIG_ENDIAN, mpic->isus[isu],
			  reg + (idx * MPIC_INFO(IRQ_STRIDE)));
}

static inline void _mpic_irq_write(struct mpic *mpic, unsigned int src_no,
				   unsigned int reg, u32 value)
{
	unsigned int	isu = src_no >> mpic->isu_shift;
	unsigned int	idx = src_no & mpic->isu_mask;

	_mpic_write(mpic->flags & MPIC_BIG_ENDIAN, mpic->isus[isu],
		    reg + (idx * MPIC_INFO(IRQ_STRIDE)), value);
}

#define mpic_read(b,r)		_mpic_read(mpic->flags & MPIC_BIG_ENDIAN,(b),(r))
#define mpic_write(b,r,v)	_mpic_write(mpic->flags & MPIC_BIG_ENDIAN,(b),(r),(v))
#define mpic_ipi_read(i)	_mpic_ipi_read(mpic,(i))
#define mpic_ipi_write(i,v)	_mpic_ipi_write(mpic,(i),(v))
#define mpic_cpu_read(i)	_mpic_cpu_read(mpic,(i))
#define mpic_cpu_write(i,v)	_mpic_cpu_write(mpic,(i),(v))
#define mpic_irq_read(s,r)	_mpic_irq_read(mpic,(s),(r))
#define mpic_irq_write(s,r,v)	_mpic_irq_write(mpic,(s),(r),(v))


/*
 * Low level utility functions
 */



/* Check if we have one of those nice broken MPICs with a flipped endian on
 * reads from IPI registers
 */
static void __init mpic_test_broken_ipi(struct mpic *mpic)
{
	u32 r;

	mpic_write(mpic->gregs, MPIC_INFO(GREG_IPI_VECTOR_PRI_0), MPIC_VECPRI_MASK);
	r = mpic_read(mpic->gregs, MPIC_INFO(GREG_IPI_VECTOR_PRI_0));

	if (r == le32_to_cpu(MPIC_VECPRI_MASK)) {
		printk(KERN_INFO "mpic: Detected reversed IPI registers\n");
		mpic->flags |= MPIC_BROKEN_IPI;
	}
}

#ifdef CONFIG_MPIC_BROKEN_U3

/* Test if an interrupt is sourced from HyperTransport (used on broken U3s)
 * to force the edge setting on the MPIC and do the ack workaround.
 */
static inline int mpic_is_ht_interrupt(struct mpic *mpic, unsigned int source)
{
	if (source >= 128 || !mpic->fixups)
		return 0;
	return mpic->fixups[source].base != NULL;
}


static inline void mpic_ht_end_irq(struct mpic *mpic, unsigned int source)
{
	struct mpic_irq_fixup *fixup = &mpic->fixups[source];

	if (fixup->applebase) {
		unsigned int soff = (fixup->index >> 3) & ~3;
		unsigned int mask = 1U << (fixup->index & 0x1f);
		writel(mask, fixup->applebase + soff);
	} else {
		spin_lock(&mpic->fixup_lock);
		writeb(0x11 + 2 * fixup->index, fixup->base + 2);
		writel(fixup->data, fixup->base + 4);
		spin_unlock(&mpic->fixup_lock);
	}
}

static void mpic_startup_ht_interrupt(struct mpic *mpic, unsigned int source,
				      unsigned int irqflags)
{
	struct mpic_irq_fixup *fixup = &mpic->fixups[source];
	unsigned long flags;
	u32 tmp;

	if (fixup->base == NULL)
		return;

	DBG("startup_ht_interrupt(0x%x, 0x%x) index: %d\n",
	    source, irqflags, fixup->index);
	spin_lock_irqsave(&mpic->fixup_lock, flags);
	/* Enable and configure */
	writeb(0x10 + 2 * fixup->index, fixup->base + 2);
	tmp = readl(fixup->base + 4);
	tmp &= ~(0x23U);
	if (irqflags & IRQ_LEVEL)
		tmp |= 0x22;
	writel(tmp, fixup->base + 4);
	spin_unlock_irqrestore(&mpic->fixup_lock, flags);
}

static void mpic_shutdown_ht_interrupt(struct mpic *mpic, unsigned int source,
				       unsigned int irqflags)
{
	struct mpic_irq_fixup *fixup = &mpic->fixups[source];
	unsigned long flags;
	u32 tmp;

	if (fixup->base == NULL)
		return;

	DBG("shutdown_ht_interrupt(0x%x, 0x%x)\n", source, irqflags);

	/* Disable */
	spin_lock_irqsave(&mpic->fixup_lock, flags);
	writeb(0x10 + 2 * fixup->index, fixup->base + 2);
	tmp = readl(fixup->base + 4);
	tmp |= 1;
	writel(tmp, fixup->base + 4);
	spin_unlock_irqrestore(&mpic->fixup_lock, flags);
}

static void __init mpic_scan_ht_pic(struct mpic *mpic, u8 __iomem *devbase,
				    unsigned int devfn, u32 vdid)
{
	int i, irq, n;
	u8 __iomem *base;
	u32 tmp;
	u8 pos;

	for (pos = readb(devbase + PCI_CAPABILITY_LIST); pos != 0;
	     pos = readb(devbase + pos + PCI_CAP_LIST_NEXT)) {
		u8 id = readb(devbase + pos + PCI_CAP_LIST_ID);
		if (id == PCI_CAP_ID_HT_IRQCONF) {
			id = readb(devbase + pos + 3);
			if (id == 0x80)
				break;
		}
	}
	if (pos == 0)
		return;

	base = devbase + pos;
	writeb(0x01, base + 2);
	n = (readl(base + 4) >> 16) & 0xff;

	printk(KERN_INFO "mpic:   - HT:%02x.%x [0x%02x] vendor %04x device %04x"
	       " has %d irqs\n",
	       devfn >> 3, devfn & 0x7, pos, vdid & 0xffff, vdid >> 16, n + 1);

	for (i = 0; i <= n; i++) {
		writeb(0x10 + 2 * i, base + 2);
		tmp = readl(base + 4);
		irq = (tmp >> 16) & 0xff;
		DBG("HT PIC index 0x%x, irq 0x%x, tmp: %08x\n", i, irq, tmp);
		/* mask it , will be unmasked later */
		tmp |= 0x1;
		writel(tmp, base + 4);
		mpic->fixups[irq].index = i;
		mpic->fixups[irq].base = base;
		/* Apple HT PIC has a non-standard way of doing EOIs */
		if ((vdid & 0xffff) == 0x106b)
			mpic->fixups[irq].applebase = devbase + 0x60;
		else
			mpic->fixups[irq].applebase = NULL;
		writeb(0x11 + 2 * i, base + 2);
		mpic->fixups[irq].data = readl(base + 4) | 0x80000000;
	}
}
 

static void __init mpic_scan_ht_pics(struct mpic *mpic)
{
	unsigned int devfn;
	u8 __iomem *cfgspace;

	printk(KERN_INFO "mpic: Setting up HT PICs workarounds for U3/U4\n");

	/* Allocate fixups array */
	mpic->fixups = alloc_bootmem(128 * sizeof(struct mpic_irq_fixup));
	BUG_ON(mpic->fixups == NULL);
	memset(mpic->fixups, 0, 128 * sizeof(struct mpic_irq_fixup));

	/* Init spinlock */
	spin_lock_init(&mpic->fixup_lock);

	/* Map U3 config space. We assume all IO-APICs are on the primary bus
	 * so we only need to map 64kB.
	 */
	cfgspace = ioremap(0xf2000000, 0x10000);
	BUG_ON(cfgspace == NULL);

	/* Now we scan all slots. We do a very quick scan, we read the header
	 * type, vendor ID and device ID only, that's plenty enough
	 */
	for (devfn = 0; devfn < 0x100; devfn++) {
		u8 __iomem *devbase = cfgspace + (devfn << 8);
		u8 hdr_type = readb(devbase + PCI_HEADER_TYPE);
		u32 l = readl(devbase + PCI_VENDOR_ID);
		u16 s;

		DBG("devfn %x, l: %x\n", devfn, l);

		/* If no device, skip */
		if (l == 0xffffffff || l == 0x00000000 ||
		    l == 0x0000ffff || l == 0xffff0000)
			goto next;
		/* Check if is supports capability lists */
		s = readw(devbase + PCI_STATUS);
		if (!(s & PCI_STATUS_CAP_LIST))
			goto next;

		mpic_scan_ht_pic(mpic, devbase, devfn, l);

	next:
		/* next device, if function 0 */
		if (PCI_FUNC(devfn) == 0 && (hdr_type & 0x80) == 0)
			devfn += 7;
	}
}

#else /* CONFIG_MPIC_BROKEN_U3 */

static inline int mpic_is_ht_interrupt(struct mpic *mpic, unsigned int source)
{
	return 0;
}

static void __init mpic_scan_ht_pics(struct mpic *mpic)
{
}

#endif /* CONFIG_MPIC_BROKEN_U3 */


#define mpic_irq_to_hw(virq)	((unsigned int)irq_map[virq].hwirq)

/* Find an mpic associated with a given linux interrupt */
static struct mpic *mpic_find(unsigned int irq, unsigned int *is_ipi)
{
	unsigned int src = mpic_irq_to_hw(irq);

	if (irq < NUM_ISA_INTERRUPTS)
		return NULL;
	if (is_ipi)
		*is_ipi = (src >= MPIC_VEC_IPI_0 && src <= MPIC_VEC_IPI_3);

	return irq_desc[irq].chip_data;
}

/* Convert a cpu mask from logical to physical cpu numbers. */
static inline u32 mpic_physmask(u32 cpumask)
{
	int i;
	u32 mask = 0;

	for (i = 0; i < NR_CPUS; ++i, cpumask >>= 1)
		mask |= (cpumask & 1) << get_hard_smp_processor_id(i);
	return mask;
}

#ifdef CONFIG_SMP
/* Get the mpic structure from the IPI number */
static inline struct mpic * mpic_from_ipi(unsigned int ipi)
{
	return irq_desc[ipi].chip_data;
}
#endif

/* Get the mpic structure from the irq number */
static inline struct mpic * mpic_from_irq(unsigned int irq)
{
	return irq_desc[irq].chip_data;
}

/* Send an EOI */
static inline void mpic_eoi(struct mpic *mpic)
{
	mpic_cpu_write(MPIC_INFO(CPU_EOI), 0);
	(void)mpic_cpu_read(MPIC_INFO(CPU_WHOAMI));
}

#ifdef CONFIG_SMP
static irqreturn_t mpic_ipi_action(int irq, void *dev_id, struct pt_regs *regs)
{
	smp_message_recv(mpic_irq_to_hw(irq) - MPIC_VEC_IPI_0, regs);
	return IRQ_HANDLED;
}
#endif /* CONFIG_SMP */

/*
 * Linux descriptor level callbacks
 */


static void mpic_unmask_irq(unsigned int irq)
{
	unsigned int loops = 100000;
	struct mpic *mpic = mpic_from_irq(irq);
	unsigned int src = mpic_irq_to_hw(irq);

	DBG("%p: %s: enable_irq: %d (src %d)\n", mpic, mpic->name, irq, src);

	mpic_irq_write(src, MPIC_INFO(IRQ_VECTOR_PRI),
		       mpic_irq_read(src, MPIC_INFO(IRQ_VECTOR_PRI)) &
		       ~MPIC_VECPRI_MASK);
	/* make sure mask gets to controller before we return to user */
	do {
		if (!loops--) {
			printk(KERN_ERR "mpic_enable_irq timeout\n");
			break;
		}
	} while(mpic_irq_read(src, MPIC_INFO(IRQ_VECTOR_PRI)) & MPIC_VECPRI_MASK);
}

static void mpic_mask_irq(unsigned int irq)
{
	unsigned int loops = 100000;
	struct mpic *mpic = mpic_from_irq(irq);
	unsigned int src = mpic_irq_to_hw(irq);

	DBG("%s: disable_irq: %d (src %d)\n", mpic->name, irq, src);

	mpic_irq_write(src, MPIC_INFO(IRQ_VECTOR_PRI),
		       mpic_irq_read(src, MPIC_INFO(IRQ_VECTOR_PRI)) |
		       MPIC_VECPRI_MASK);

	/* make sure mask gets to controller before we return to user */
	do {
		if (!loops--) {
			printk(KERN_ERR "mpic_enable_irq timeout\n");
			break;
		}
	} while(!(mpic_irq_read(src, MPIC_INFO(IRQ_VECTOR_PRI)) & MPIC_VECPRI_MASK));
}

static void mpic_end_irq(unsigned int irq)
{
	struct mpic *mpic = mpic_from_irq(irq);

#ifdef DEBUG_IRQ
	DBG("%s: end_irq: %d\n", mpic->name, irq);
#endif
	/* We always EOI on end_irq() even for edge interrupts since that
	 * should only lower the priority, the MPIC should have properly
	 * latched another edge interrupt coming in anyway
	 */

	mpic_eoi(mpic);
}

#ifdef CONFIG_MPIC_BROKEN_U3

static void mpic_unmask_ht_irq(unsigned int irq)
{
	struct mpic *mpic = mpic_from_irq(irq);
	unsigned int src = mpic_irq_to_hw(irq);

	mpic_unmask_irq(irq);

	if (irq_desc[irq].status & IRQ_LEVEL)
		mpic_ht_end_irq(mpic, src);
}

static unsigned int mpic_startup_ht_irq(unsigned int irq)
{
	struct mpic *mpic = mpic_from_irq(irq);
	unsigned int src = mpic_irq_to_hw(irq);

	mpic_unmask_irq(irq);
	mpic_startup_ht_interrupt(mpic, src, irq_desc[irq].status);

	return 0;
}

static void mpic_shutdown_ht_irq(unsigned int irq)
{
	struct mpic *mpic = mpic_from_irq(irq);
	unsigned int src = mpic_irq_to_hw(irq);

	mpic_shutdown_ht_interrupt(mpic, src, irq_desc[irq].status);
	mpic_mask_irq(irq);
}

static void mpic_end_ht_irq(unsigned int irq)
{
	struct mpic *mpic = mpic_from_irq(irq);
	unsigned int src = mpic_irq_to_hw(irq);

#ifdef DEBUG_IRQ
	DBG("%s: end_irq: %d\n", mpic->name, irq);
#endif
	/* We always EOI on end_irq() even for edge interrupts since that
	 * should only lower the priority, the MPIC should have properly
	 * latched another edge interrupt coming in anyway
	 */

	if (irq_desc[irq].status & IRQ_LEVEL)
		mpic_ht_end_irq(mpic, src);
	mpic_eoi(mpic);
}
#endif /* !CONFIG_MPIC_BROKEN_U3 */

#ifdef CONFIG_SMP

static void mpic_unmask_ipi(unsigned int irq)
{
	struct mpic *mpic = mpic_from_ipi(irq);
	unsigned int src = mpic_irq_to_hw(irq) - MPIC_VEC_IPI_0;

	DBG("%s: enable_ipi: %d (ipi %d)\n", mpic->name, irq, src);
	mpic_ipi_write(src, mpic_ipi_read(src) & ~MPIC_VECPRI_MASK);
}

static void mpic_mask_ipi(unsigned int irq)
{
	/* NEVER disable an IPI... that's just plain wrong! */
}

static void mpic_end_ipi(unsigned int irq)
{
	struct mpic *mpic = mpic_from_ipi(irq);

	/*
	 * IPIs are marked IRQ_PER_CPU. This has the side effect of
	 * preventing the IRQ_PENDING/IRQ_INPROGRESS logic from
	 * applying to them. We EOI them late to avoid re-entering.
	 * We mark IPI's with IRQF_DISABLED as they must run with
	 * irqs disabled.
	 */
	mpic_eoi(mpic);
}

#endif /* CONFIG_SMP */

static void mpic_set_affinity(unsigned int irq, cpumask_t cpumask)
{
	struct mpic *mpic = mpic_from_irq(irq);
	unsigned int src = mpic_irq_to_hw(irq);

	cpumask_t tmp;

	cpus_and(tmp, cpumask, cpu_online_map);

	mpic_irq_write(src, MPIC_INFO(IRQ_DESTINATION),
		       mpic_physmask(cpus_addr(tmp)[0]));	
}

static unsigned int mpic_type_to_vecpri(struct mpic *mpic, unsigned int type)
{
	/* Now convert sense value */
	switch(type & IRQ_TYPE_SENSE_MASK) {
	case IRQ_TYPE_EDGE_RISING:
		return MPIC_INFO(VECPRI_SENSE_EDGE) |
		       MPIC_INFO(VECPRI_POLARITY_POSITIVE);
	case IRQ_TYPE_EDGE_FALLING:
	case IRQ_TYPE_EDGE_BOTH:
		return MPIC_INFO(VECPRI_SENSE_EDGE) |
		       MPIC_INFO(VECPRI_POLARITY_NEGATIVE);
	case IRQ_TYPE_LEVEL_HIGH:
		return MPIC_INFO(VECPRI_SENSE_LEVEL) |
		       MPIC_INFO(VECPRI_POLARITY_POSITIVE);
	case IRQ_TYPE_LEVEL_LOW:
	default:
		return MPIC_INFO(VECPRI_SENSE_LEVEL) |
		       MPIC_INFO(VECPRI_POLARITY_NEGATIVE);
	}
}

static int mpic_set_irq_type(unsigned int virq, unsigned int flow_type)
{
	struct mpic *mpic = mpic_from_irq(virq);
	unsigned int src = mpic_irq_to_hw(virq);
	struct irq_desc *desc = get_irq_desc(virq);
	unsigned int vecpri, vold, vnew;

	DBG("mpic: set_irq_type(mpic:@%p,virq:%d,src:0x%x,type:0x%x)\n",
	    mpic, virq, src, flow_type);

	if (src >= mpic->irq_count)
		return -EINVAL;

	if (flow_type == IRQ_TYPE_NONE)
		if (mpic->senses && src < mpic->senses_count)
			flow_type = mpic->senses[src];
	if (flow_type == IRQ_TYPE_NONE)
		flow_type = IRQ_TYPE_LEVEL_LOW;

	desc->status &= ~(IRQ_TYPE_SENSE_MASK | IRQ_LEVEL);
	desc->status |= flow_type & IRQ_TYPE_SENSE_MASK;
	if (flow_type & (IRQ_TYPE_LEVEL_HIGH | IRQ_TYPE_LEVEL_LOW))
		desc->status |= IRQ_LEVEL;

	if (mpic_is_ht_interrupt(mpic, src))
		vecpri = MPIC_VECPRI_POLARITY_POSITIVE |
			MPIC_VECPRI_SENSE_EDGE;
	else
		vecpri = mpic_type_to_vecpri(mpic, flow_type);

	vold = mpic_irq_read(src, MPIC_INFO(IRQ_VECTOR_PRI));
	vnew = vold & ~(MPIC_INFO(VECPRI_POLARITY_MASK) |
			MPIC_INFO(VECPRI_SENSE_MASK));
	vnew |= vecpri;
	if (vold != vnew)
		mpic_irq_write(src, MPIC_INFO(IRQ_VECTOR_PRI), vnew);

	return 0;
}

static struct irq_chip mpic_irq_chip = {
	.mask		= mpic_mask_irq,
	.unmask		= mpic_unmask_irq,
	.eoi		= mpic_end_irq,
	.set_type	= mpic_set_irq_type,
};

#ifdef CONFIG_SMP
static struct irq_chip mpic_ipi_chip = {
	.mask		= mpic_mask_ipi,
	.unmask		= mpic_unmask_ipi,
	.eoi		= mpic_end_ipi,
};
#endif /* CONFIG_SMP */

#ifdef CONFIG_MPIC_BROKEN_U3
static struct irq_chip mpic_irq_ht_chip = {
	.startup	= mpic_startup_ht_irq,
	.shutdown	= mpic_shutdown_ht_irq,
	.mask		= mpic_mask_irq,
	.unmask		= mpic_unmask_ht_irq,
	.eoi		= mpic_end_ht_irq,
	.set_type	= mpic_set_irq_type,
};
#endif /* CONFIG_MPIC_BROKEN_U3 */


static int mpic_host_match(struct irq_host *h, struct device_node *node)
{
	struct mpic *mpic = h->host_data;

	/* Exact match, unless mpic node is NULL */
	return mpic->of_node == NULL || mpic->of_node == node;
}

static int mpic_host_map(struct irq_host *h, unsigned int virq,
			 irq_hw_number_t hw)
{
	struct mpic *mpic = h->host_data;
	struct irq_chip *chip;

	DBG("mpic: map virq %d, hwirq 0x%lx\n", virq, hw);

	if (hw == MPIC_VEC_SPURRIOUS)
		return -EINVAL;

#ifdef CONFIG_SMP
	else if (hw >= MPIC_VEC_IPI_0) {
		WARN_ON(!(mpic->flags & MPIC_PRIMARY));

		if (mpic->flags & MPIC_SKIP_IPI_INIT)
			return 0;

		DBG("mpic: mapping as IPI\n");
		set_irq_chip_data(virq, mpic);
		set_irq_chip_and_handler(virq, &mpic->hc_ipi,
					 handle_percpu_irq);
		return 0;
	}
#endif /* CONFIG_SMP */

	if (hw >= mpic->irq_count)
		return -EINVAL;

	/* Default chip */
	chip = &mpic->hc_irq;

#ifdef CONFIG_MPIC_BROKEN_U3
	/* Check for HT interrupts, override vecpri */
	if (mpic_is_ht_interrupt(mpic, hw))
		chip = &mpic->hc_ht_irq;
#endif /* CONFIG_MPIC_BROKEN_U3 */

	DBG("mpic: mapping to irq chip @%p\n", chip);

	set_irq_chip_data(virq, mpic);
	set_irq_chip_and_handler(virq, chip, handle_fasteoi_irq);

	/* Set default irq type */
	set_irq_type(virq, IRQ_TYPE_NONE);

	return 0;
}

static int mpic_host_xlate(struct irq_host *h, struct device_node *ct,
			   u32 *intspec, unsigned int intsize,
			   irq_hw_number_t *out_hwirq, unsigned int *out_flags)

{
	static unsigned char map_mpic_senses[4] = {
		IRQ_TYPE_EDGE_RISING,
		IRQ_TYPE_LEVEL_LOW,
		IRQ_TYPE_LEVEL_HIGH,
		IRQ_TYPE_EDGE_FALLING,
	};

	*out_hwirq = intspec[0];
	if (intsize > 1) {
		u32 mask = 0x3;

		/* Apple invented a new race of encoding on machines with
		 * an HT APIC. They encode, among others, the index within
		 * the HT APIC. We don't care about it here since thankfully,
		 * it appears that they have the APIC already properly
		 * configured, and thus our current fixup code that reads the
		 * APIC config works fine. However, we still need to mask out
		 * bits in the specifier to make sure we only get bit 0 which
		 * is the level/edge bit (the only sense bit exposed by Apple),
		 * as their bit 1 means something else.
		 */
		if (machine_is(powermac))
			mask = 0x1;
		*out_flags = map_mpic_senses[intspec[1] & mask];
	} else
		*out_flags = IRQ_TYPE_NONE;

	DBG("mpic: xlate (%d cells: 0x%08x 0x%08x) to line 0x%lx sense 0x%x\n",
	    intsize, intspec[0], intspec[1], *out_hwirq, *out_flags);

	return 0;
}

static struct irq_host_ops mpic_host_ops = {
	.match = mpic_host_match,
	.map = mpic_host_map,
	.xlate = mpic_host_xlate,
};

/*
 * Exported functions
 */

struct mpic * __init mpic_alloc(struct device_node *node,
				unsigned long phys_addr,
				unsigned int flags,
				unsigned int isu_size,
				unsigned int irq_count,
				const char *name)
{
	struct mpic	*mpic;
	u32		reg;
	const char	*vers;
	int		i;

	mpic = alloc_bootmem(sizeof(struct mpic));
	if (mpic == NULL)
		return NULL;
	
	memset(mpic, 0, sizeof(struct mpic));
	mpic->name = name;
	mpic->of_node = node ? of_node_get(node) : NULL;

	mpic->irqhost = irq_alloc_host(IRQ_HOST_MAP_LINEAR, 256,
				       &mpic_host_ops,
				       MPIC_VEC_SPURRIOUS);
	if (mpic->irqhost == NULL) {
		of_node_put(node);
		return NULL;
	}

	mpic->irqhost->host_data = mpic;
	mpic->hc_irq = mpic_irq_chip;
	mpic->hc_irq.typename = name;
	if (flags & MPIC_PRIMARY)
		mpic->hc_irq.set_affinity = mpic_set_affinity;
#ifdef CONFIG_MPIC_BROKEN_U3
	mpic->hc_ht_irq = mpic_irq_ht_chip;
	mpic->hc_ht_irq.typename = name;
	if (flags & MPIC_PRIMARY)
		mpic->hc_ht_irq.set_affinity = mpic_set_affinity;
#endif /* CONFIG_MPIC_BROKEN_U3 */
#ifdef CONFIG_SMP
	mpic->hc_ipi = mpic_ipi_chip;
	mpic->hc_ipi.typename = name;
#endif /* CONFIG_SMP */

	mpic->flags = flags;
	mpic->isu_size = isu_size;
	mpic->irq_count = irq_count;
	mpic->num_sources = 0; /* so far */

#ifdef CONFIG_MPIC_WEIRD
	mpic->hw_set = mpic_infos[MPIC_GET_REGSET(flags)];
#endif

	/* Map the global registers */
	mpic->gregs = ioremap(phys_addr + MPIC_INFO(GREG_BASE), 0x1000);
	mpic->tmregs = mpic->gregs +
		       ((MPIC_INFO(TIMER_BASE) - MPIC_INFO(GREG_BASE)) >> 2);
	BUG_ON(mpic->gregs == NULL);

	/* Reset */
	if (flags & MPIC_WANTS_RESET) {
		mpic_write(mpic->gregs, MPIC_INFO(GREG_GLOBAL_CONF_0),
			   mpic_read(mpic->gregs, MPIC_INFO(GREG_GLOBAL_CONF_0))
			   | MPIC_GREG_GCONF_RESET);
		while( mpic_read(mpic->gregs, MPIC_INFO(GREG_GLOBAL_CONF_0))
		       & MPIC_GREG_GCONF_RESET)
			mb();
	}

	/* Read feature register, calculate num CPUs and, for non-ISU
	 * MPICs, num sources as well. On ISU MPICs, sources are counted
	 * as ISUs are added
	 */
	reg = mpic_read(mpic->gregs, MPIC_INFO(GREG_FEATURE_0));
	mpic->num_cpus = ((reg & MPIC_GREG_FEATURE_LAST_CPU_MASK)
			  >> MPIC_GREG_FEATURE_LAST_CPU_SHIFT) + 1;
	if (isu_size == 0)
		mpic->num_sources = ((reg & MPIC_GREG_FEATURE_LAST_SRC_MASK)
				     >> MPIC_GREG_FEATURE_LAST_SRC_SHIFT) + 1;

	/* Map the per-CPU registers */
	for (i = 0; i < mpic->num_cpus; i++) {
		mpic->cpuregs[i] = ioremap(phys_addr + MPIC_INFO(CPU_BASE) +
					   i * MPIC_INFO(CPU_STRIDE), 0x1000);
		BUG_ON(mpic->cpuregs[i] == NULL);
	}

	/* Initialize main ISU if none provided */
	if (mpic->isu_size == 0) {
		mpic->isu_size = mpic->num_sources;
		mpic->isus[0] = ioremap(phys_addr + MPIC_INFO(IRQ_BASE),
					MPIC_INFO(IRQ_STRIDE) * mpic->isu_size);
		BUG_ON(mpic->isus[0] == NULL);
	}
	mpic->isu_shift = 1 + __ilog2(mpic->isu_size - 1);
	mpic->isu_mask = (1 << mpic->isu_shift) - 1;

	/* Display version */
	switch (reg & MPIC_GREG_FEATURE_VERSION_MASK) {
	case 1:
		vers = "1.0";
		break;
	case 2:
		vers = "1.2";
		break;
	case 3:
		vers = "1.3";
		break;
	default:
		vers = "<unknown>";
		break;
	}
	printk(KERN_INFO "mpic: Setting up MPIC \"%s\" version %s at %lx, max %d CPUs\n",
	       name, vers, phys_addr, mpic->num_cpus);
	printk(KERN_INFO "mpic: ISU size: %d, shift: %d, mask: %x\n", mpic->isu_size,
	       mpic->isu_shift, mpic->isu_mask);

	mpic->next = mpics;
	mpics = mpic;

	if (flags & MPIC_PRIMARY) {
		mpic_primary = mpic;
		irq_set_default_host(mpic->irqhost);
	}

	return mpic;
}

void __init mpic_assign_isu(struct mpic *mpic, unsigned int isu_num,
			    unsigned long phys_addr)
{
	unsigned int isu_first = isu_num * mpic->isu_size;

	BUG_ON(isu_num >= MPIC_MAX_ISU);

	mpic->isus[isu_num] = ioremap(phys_addr,
				      MPIC_INFO(IRQ_STRIDE) * mpic->isu_size);
	if ((isu_first + mpic->isu_size) > mpic->num_sources)
		mpic->num_sources = isu_first + mpic->isu_size;
}

void __init mpic_set_default_senses(struct mpic *mpic, u8 *senses, int count)
{
	mpic->senses = senses;
	mpic->senses_count = count;
}

void __init mpic_init(struct mpic *mpic)
{
	int i;

	BUG_ON(mpic->num_sources == 0);
	WARN_ON(mpic->num_sources > MPIC_VEC_IPI_0);

	/* Sanitize source count */
	if (mpic->num_sources > MPIC_VEC_IPI_0)
		mpic->num_sources = MPIC_VEC_IPI_0;

	printk(KERN_INFO "mpic: Initializing for %d sources\n", mpic->num_sources);

	/* Set current processor priority to max */
	mpic_cpu_write(MPIC_INFO(CPU_CURRENT_TASK_PRI), 0xf);

	/* Initialize timers: just disable them all */
	for (i = 0; i < 4; i++) {
		mpic_write(mpic->tmregs,
			   i * MPIC_INFO(TIMER_STRIDE) +
			   MPIC_INFO(TIMER_DESTINATION), 0);
		mpic_write(mpic->tmregs,
			   i * MPIC_INFO(TIMER_STRIDE) +
			   MPIC_INFO(TIMER_VECTOR_PRI),
			   MPIC_VECPRI_MASK |
			   (MPIC_VEC_TIMER_0 + i));
	}

	if (mpic->flags & MPIC_SKIP_IPI_INIT)
		goto ipi_bailout;

	/* Initialize IPIs to our reserved vectors and mark them disabled for now */
	mpic_test_broken_ipi(mpic);
	for (i = 0; i < 4; i++) {
		mpic_ipi_write(i,
			       MPIC_VECPRI_MASK |
			       (10 << MPIC_VECPRI_PRIORITY_SHIFT) |
			       (MPIC_VEC_IPI_0 + i));
	}

ipi_bailout:
	/* Initialize interrupt sources */
	if (mpic->irq_count == 0)
		mpic->irq_count = mpic->num_sources;

	/* Do the HT PIC fixups on U3 broken mpic */
	DBG("MPIC flags: %x\n", mpic->flags);
	if ((mpic->flags & MPIC_BROKEN_U3) && (mpic->flags & MPIC_PRIMARY))
 		mpic_scan_ht_pics(mpic);

	for (i = 0; i < mpic->num_sources; i++) {
		/* start with vector = source number, and masked */
		u32 vecpri = MPIC_VECPRI_MASK | i |
			(8 << MPIC_VECPRI_PRIORITY_SHIFT);
		
		/* init hw */
		mpic_irq_write(i, MPIC_INFO(IRQ_VECTOR_PRI), vecpri);
		mpic_irq_write(i, MPIC_INFO(IRQ_DESTINATION),
			       1 << hard_smp_processor_id());
	}
	
	/* Init spurrious vector */
	mpic_write(mpic->gregs, MPIC_INFO(GREG_SPURIOUS), MPIC_VEC_SPURRIOUS);

	/* Disable 8259 passthrough, if supported */
	if (!(mpic->flags & MPIC_NO_PTHROU_DIS))
		mpic_write(mpic->gregs, MPIC_INFO(GREG_GLOBAL_CONF_0),
			   mpic_read(mpic->gregs, MPIC_INFO(GREG_GLOBAL_CONF_0))
			   | MPIC_GREG_GCONF_8259_PTHROU_DIS);

	/* Set current processor priority to 0 */
	mpic_cpu_write(MPIC_INFO(CPU_CURRENT_TASK_PRI), 0);
}

void __init mpic_set_clk_ratio(struct mpic *mpic, u32 clock_ratio)
{
	u32 v;

	v = mpic_read(mpic->gregs, MPIC_GREG_GLOBAL_CONF_1);
	v &= ~MPIC_GREG_GLOBAL_CONF_1_CLK_RATIO_MASK;
	v |= MPIC_GREG_GLOBAL_CONF_1_CLK_RATIO(clock_ratio);
	mpic_write(mpic->gregs, MPIC_GREG_GLOBAL_CONF_1, v);
}

void __init mpic_set_serial_int(struct mpic *mpic, int enable)
{
	unsigned long flags;
	u32 v;

	spin_lock_irqsave(&mpic_lock, flags);
	v = mpic_read(mpic->gregs, MPIC_GREG_GLOBAL_CONF_1);
	if (enable)
		v |= MPIC_GREG_GLOBAL_CONF_1_SIE;
	else
		v &= ~MPIC_GREG_GLOBAL_CONF_1_SIE;
	mpic_write(mpic->gregs, MPIC_GREG_GLOBAL_CONF_1, v);
	spin_unlock_irqrestore(&mpic_lock, flags);
}

void mpic_irq_set_priority(unsigned int irq, unsigned int pri)
{
	int is_ipi;
	struct mpic *mpic = mpic_find(irq, &is_ipi);
	unsigned int src = mpic_irq_to_hw(irq);
	unsigned long flags;
	u32 reg;

	spin_lock_irqsave(&mpic_lock, flags);
	if (is_ipi) {
		reg = mpic_ipi_read(src - MPIC_VEC_IPI_0) &
			~MPIC_VECPRI_PRIORITY_MASK;
		mpic_ipi_write(src - MPIC_VEC_IPI_0,
			       reg | (pri << MPIC_VECPRI_PRIORITY_SHIFT));
	} else {
		reg = mpic_irq_read(src, MPIC_INFO(IRQ_VECTOR_PRI))
			& ~MPIC_VECPRI_PRIORITY_MASK;
		mpic_irq_write(src, MPIC_INFO(IRQ_VECTOR_PRI),
			       reg | (pri << MPIC_VECPRI_PRIORITY_SHIFT));
	}
	spin_unlock_irqrestore(&mpic_lock, flags);
}

unsigned int mpic_irq_get_priority(unsigned int irq)
{
	int is_ipi;
	struct mpic *mpic = mpic_find(irq, &is_ipi);
	unsigned int src = mpic_irq_to_hw(irq);
	unsigned long flags;
	u32 reg;

	spin_lock_irqsave(&mpic_lock, flags);
	if (is_ipi)
		reg = mpic_ipi_read(src = MPIC_VEC_IPI_0);
	else
		reg = mpic_irq_read(src, MPIC_INFO(IRQ_VECTOR_PRI));
	spin_unlock_irqrestore(&mpic_lock, flags);
	return (reg & MPIC_VECPRI_PRIORITY_MASK) >> MPIC_VECPRI_PRIORITY_SHIFT;
}

void mpic_setup_this_cpu(void)
{
#ifdef CONFIG_SMP
	struct mpic *mpic = mpic_primary;
	unsigned long flags;
	u32 msk = 1 << hard_smp_processor_id();
	unsigned int i;

	BUG_ON(mpic == NULL);

	DBG("%s: setup_this_cpu(%d)\n", mpic->name, hard_smp_processor_id());

	spin_lock_irqsave(&mpic_lock, flags);

 	/* let the mpic know we want intrs. default affinity is 0xffffffff
	 * until changed via /proc. That's how it's done on x86. If we want
	 * it differently, then we should make sure we also change the default
	 * values of irq_desc[].affinity in irq.c.
 	 */
	if (distribute_irqs) {
	 	for (i = 0; i < mpic->num_sources ; i++)
			mpic_irq_write(i, MPIC_INFO(IRQ_DESTINATION),
				mpic_irq_read(i, MPIC_INFO(IRQ_DESTINATION)) | msk);
	}

	/* Set current processor priority to 0 */
	mpic_cpu_write(MPIC_INFO(CPU_CURRENT_TASK_PRI), 0);

	spin_unlock_irqrestore(&mpic_lock, flags);
#endif /* CONFIG_SMP */
}

int mpic_cpu_get_priority(void)
{
	struct mpic *mpic = mpic_primary;

	return mpic_cpu_read(MPIC_INFO(CPU_CURRENT_TASK_PRI));
}

void mpic_cpu_set_priority(int prio)
{
	struct mpic *mpic = mpic_primary;

	prio &= MPIC_CPU_TASKPRI_MASK;
	mpic_cpu_write(MPIC_INFO(CPU_CURRENT_TASK_PRI), prio);
}

/*
 * XXX: someone who knows mpic should check this.
 * do we need to eoi the ipi including for kexec cpu here (see xics comments)?
 * or can we reset the mpic in the new kernel?
 */
void mpic_teardown_this_cpu(int secondary)
{
	struct mpic *mpic = mpic_primary;
	unsigned long flags;
	u32 msk = 1 << hard_smp_processor_id();
	unsigned int i;

	BUG_ON(mpic == NULL);

	DBG("%s: teardown_this_cpu(%d)\n", mpic->name, hard_smp_processor_id());
	spin_lock_irqsave(&mpic_lock, flags);

	/* let the mpic know we don't want intrs.  */
	for (i = 0; i < mpic->num_sources ; i++)
		mpic_irq_write(i, MPIC_INFO(IRQ_DESTINATION),
			mpic_irq_read(i, MPIC_INFO(IRQ_DESTINATION)) & ~msk);

	/* Set current processor priority to max */
	mpic_cpu_write(MPIC_INFO(CPU_CURRENT_TASK_PRI), 0xf);

	spin_unlock_irqrestore(&mpic_lock, flags);
}


void mpic_send_ipi(unsigned int ipi_no, unsigned int cpu_mask)
{
	struct mpic *mpic = mpic_primary;

	BUG_ON(mpic == NULL);

#ifdef DEBUG_IPI
	DBG("%s: send_ipi(ipi_no: %d)\n", mpic->name, ipi_no);
#endif

	mpic_cpu_write(MPIC_INFO(CPU_IPI_DISPATCH_0) +
		       ipi_no * MPIC_INFO(CPU_IPI_DISPATCH_STRIDE),
		       mpic_physmask(cpu_mask & cpus_addr(cpu_online_map)[0]));
}

unsigned int mpic_get_one_irq(struct mpic *mpic, struct pt_regs *regs)
{
	u32 src;

	src = mpic_cpu_read(MPIC_INFO(CPU_INTACK)) & MPIC_INFO(VECPRI_VECTOR_MASK);
#ifdef DEBUG_LOW
	DBG("%s: get_one_irq(): %d\n", mpic->name, src);
#endif
	if (unlikely(src == MPIC_VEC_SPURRIOUS))
		return NO_IRQ;
	return irq_linear_revmap(mpic->irqhost, src);
}

unsigned int mpic_get_irq(struct pt_regs *regs)
{
	struct mpic *mpic = mpic_primary;

	BUG_ON(mpic == NULL);

	return mpic_get_one_irq(mpic, regs);
}


#ifdef CONFIG_SMP
void mpic_request_ipis(void)
{
	struct mpic *mpic = mpic_primary;
	int i;
	static char *ipi_names[] = {
		"IPI0 (call function)",
		"IPI1 (reschedule)",
		"IPI2 (unused)",
		"IPI3 (debugger break)",
	};
	BUG_ON(mpic == NULL);

	printk(KERN_INFO "mpic: requesting IPIs ... \n");

	for (i = 0; i < 4; i++) {
		unsigned int vipi = irq_create_mapping(mpic->irqhost,
						       MPIC_VEC_IPI_0 + i);
		if (vipi == NO_IRQ) {
			printk(KERN_ERR "Failed to map IPI %d\n", i);
			break;
		}
		request_irq(vipi, mpic_ipi_action, IRQF_DISABLED,
			    ipi_names[i], mpic);
	}
}

void smp_mpic_message_pass(int target, int msg)
{
	/* make sure we're sending something that translates to an IPI */
	if ((unsigned int)msg > 3) {
		printk("SMP %d: smp_message_pass: unknown msg %d\n",
		       smp_processor_id(), msg);
		return;
	}
	switch (target) {
	case MSG_ALL:
		mpic_send_ipi(msg, 0xffffffff);
		break;
	case MSG_ALL_BUT_SELF:
		mpic_send_ipi(msg, 0xffffffff & ~(1 << smp_processor_id()));
		break;
	default:
		mpic_send_ipi(msg, 1 << target);
		break;
	}
}
#endif /* CONFIG_SMP */
