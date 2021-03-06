#ifndef _I386_PAGE_H
#define _I386_PAGE_H

/* PAGE_SHIFT determines the page size */
#define PAGE_SHIFT	12
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))

#ifdef CONFIG_X86_PAE
#define __PHYSICAL_MASK_SHIFT	40
#define __PHYSICAL_MASK		((1ULL << __PHYSICAL_MASK_SHIFT) - 1)
#define PHYSICAL_PAGE_MASK	(~((1ULL << PAGE_SHIFT) - 1) & __PHYSICAL_MASK)
#else
#define __PHYSICAL_MASK_SHIFT	32
#define __PHYSICAL_MASK		(~0UL)
#define PHYSICAL_PAGE_MASK	(PAGE_MASK & __PHYSICAL_MASK)
#endif

#define LARGE_PAGE_MASK (~(LARGE_PAGE_SIZE-1))
#define LARGE_PAGE_SIZE (1UL << PMD_SHIFT)

#ifdef __KERNEL__

/*
 * Need to repeat this here in order to not include pgtable.h (which in turn
 * depends on definitions made here), but to be able to use the symbolic
 * below. The preprocessor will warn if the two definitions aren't identical.
 */
#define _PAGE_PRESENT	0x001
#define _PAGE_IO	0x200

#ifndef __ASSEMBLY__

#include <linux/string.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/bug.h>
#include <xen/interface/xen.h>
#include <xen/features.h>

#ifdef CONFIG_X86_USE_3DNOW

#include <asm/mmx.h>

#define clear_page(page)	mmx_clear_page((void *)(page))
#define copy_page(to,from)	mmx_copy_page(to,from)

#else

#define alloc_zeroed_user_highpage(vma, vaddr) alloc_page_vma(GFP_HIGHUSER | __GFP_ZERO, vma, vaddr)
#define __HAVE_ARCH_ALLOC_ZEROED_USER_HIGHPAGE

/*
 *	On older X86 processors it's not a win to use MMX here it seems.
 *	Maybe the K6-III ?
 */
 
#define clear_page(page)	memset((void *)(page), 0, PAGE_SIZE)
#define copy_page(to,from)	memcpy((void *)(to), (void *)(from), PAGE_SIZE)

#endif

#define clear_user_page(page, vaddr, pg)	clear_page(page)
#define copy_user_page(to, from, vaddr, pg)	copy_page(to, from)

/*
 * These are used to make use of C type-checking..
 */
extern int nx_enabled;
#ifdef CONFIG_X86_PAE
extern unsigned long long __supported_pte_mask;
typedef struct { unsigned long pte_low, pte_high; } pte_t;
typedef struct { unsigned long long pmd; } pmd_t;
typedef struct { unsigned long long pgd; } pgd_t;
typedef struct { unsigned long long pgprot; } pgprot_t;
#define pgprot_val(x)	((x).pgprot)
#include <asm/maddr.h>
#define __pte(x) ({ unsigned long long _x = (x);			\
    if ((_x & (_PAGE_PRESENT|_PAGE_IO)) == _PAGE_PRESENT)		\
        _x = pte_phys_to_machine(_x);					\
    ((pte_t) {(unsigned long)(_x), (unsigned long)(_x>>32)}); })
#define __pgd(x) ({ unsigned long long _x = (x); \
    (pgd_t) {((_x) & _PAGE_PRESENT) ? pte_phys_to_machine(_x) : (_x)}; })
#define __pmd(x) ({ unsigned long long _x = (x); \
    (pmd_t) {((_x) & _PAGE_PRESENT) ? pte_phys_to_machine(_x) : (_x)}; })
static inline unsigned long long __pte_val(pte_t x)
{
	return ((unsigned long long)x.pte_high << 32) | x.pte_low;
}
static inline unsigned long long pte_val(pte_t x)
{
	unsigned long long ret = __pte_val(x);
	if ((x.pte_low & (_PAGE_PRESENT|_PAGE_IO)) == _PAGE_PRESENT)
		ret = pte_machine_to_phys(ret);
	return ret;
}
#define __pmd_val(x) ((x).pmd)
static inline unsigned long long pmd_val(pmd_t x)
{
	unsigned long long ret = __pmd_val(x);
#if CONFIG_XEN_COMPAT <= 0x030002
	if (ret) ret = pte_machine_to_phys(ret) | _PAGE_PRESENT;
#else
	if (ret & _PAGE_PRESENT) ret = pte_machine_to_phys(ret);
#endif
	return ret;
}
#define __pud_val(x) __pgd_val((x).pgd)
#define __pgd_val(x) ((x).pgd)
static inline unsigned long long pgd_val(pgd_t x)
{
	unsigned long long ret = __pgd_val(x);
	if (ret & _PAGE_PRESENT) ret = pte_machine_to_phys(ret);
	return ret;
}
#define HPAGE_SHIFT	21
#else
typedef struct { unsigned long pte_low; } pte_t;
typedef struct { unsigned long pgd; } pgd_t;
typedef struct { unsigned long pgprot; } pgprot_t;
#define pgprot_val(x)	((x).pgprot)
#include <asm/maddr.h>
#define boot_pte_t pte_t /* or would you rather have a typedef */
#define __pte_val(x) ((x).pte_low)
#define pte_val(x) ((__pte_val(x) & (_PAGE_PRESENT|_PAGE_IO))	\
		    == _PAGE_PRESENT ?				\
		    machine_to_phys(__pte_val(x)) :		\
		    __pte_val(x))
#define __pte(x) ({ unsigned long _x = (x);			\
    if ((_x & (_PAGE_PRESENT|_PAGE_IO)) == _PAGE_PRESENT)	\
        _x = phys_to_machine(_x);				\
    ((pte_t) { _x }); })
#define __pmd_val(x) __pud_val((x).pud)
#define __pud_val(x) __pgd_val((x).pgd)
#define __pgd(x) ({ unsigned long _x = (x); \
    (pgd_t) {((_x) & _PAGE_PRESENT) ? phys_to_machine(_x) : (_x)}; })
#define __pgd_val(x) ((x).pgd)
static inline unsigned long pgd_val(pgd_t x)
{
	unsigned long ret = __pgd_val(x);
#if CONFIG_XEN_COMPAT <= 0x030002
	if (ret) ret = machine_to_phys(ret) | _PAGE_PRESENT;
#else
	if (ret & _PAGE_PRESENT) ret = machine_to_phys(ret);
#endif
	return ret;
}
#define HPAGE_SHIFT	22
#endif
#define PTE_MASK	PHYSICAL_PAGE_MASK

#ifdef CONFIG_HUGETLB_PAGE
#define HPAGE_SIZE	((1UL) << HPAGE_SHIFT)
#define HPAGE_MASK	(~(HPAGE_SIZE - 1))
#define HUGETLB_PAGE_ORDER	(HPAGE_SHIFT - PAGE_SHIFT)
#define HAVE_ARCH_HUGETLB_UNMAPPED_AREA
#endif

#define __pgprot(x)	((pgprot_t) { (x) } )

#endif /* !__ASSEMBLY__ */

/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN(addr)	(((addr)+PAGE_SIZE-1)&PAGE_MASK)

/*
 * This handles the memory map.. We could make this a config
 * option, but too many people screw it up, and too few need
 * it.
 *
 * A __PAGE_OFFSET of 0xC0000000 means that the kernel has
 * a virtual address space of one gigabyte, which limits the
 * amount of physical memory you can use to about 950MB. 
 *
 * If you want more physical memory than this then see the CONFIG_HIGHMEM4G
 * and CONFIG_HIGHMEM64G options in the kernel configuration.
 */

#ifndef __ASSEMBLY__

struct vm_area_struct;

/*
 * This much address space is reserved for vmalloc() and iomap()
 * as well as fixmap mappings.
 */
extern unsigned int __VMALLOC_RESERVE;

extern int sysctl_legacy_va_layout;

extern int page_is_ram(unsigned long pagenr);

#endif /* __ASSEMBLY__ */

#ifdef __ASSEMBLY__
#define __PAGE_OFFSET		CONFIG_PAGE_OFFSET
#define __PHYSICAL_START	CONFIG_PHYSICAL_START
#else
#define __PAGE_OFFSET		((unsigned long)CONFIG_PAGE_OFFSET)
#define __PHYSICAL_START	((unsigned long)CONFIG_PHYSICAL_START)
#endif
#define __KERNEL_START		(__PAGE_OFFSET + __PHYSICAL_START)

#if CONFIG_XEN_COMPAT <= 0x030002
#undef LOAD_OFFSET
#define LOAD_OFFSET		0
#endif

#define PAGE_OFFSET		((unsigned long)__PAGE_OFFSET)
#define VMALLOC_RESERVE		((unsigned long)__VMALLOC_RESERVE)
#define MAXMEM			(__FIXADDR_TOP-__PAGE_OFFSET-__VMALLOC_RESERVE)
#define __pa(x)			((unsigned long)(x)-PAGE_OFFSET)
#define __va(x)			((void *)((unsigned long)(x)+PAGE_OFFSET))
#define pfn_to_kaddr(pfn)      __va((pfn) << PAGE_SHIFT)
#ifdef CONFIG_FLATMEM
#define pfn_valid(pfn)		((pfn) < max_mapnr)
#endif /* CONFIG_FLATMEM */
#define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)

#define virt_addr_valid(kaddr)	pfn_valid(__pa(kaddr) >> PAGE_SHIFT)

#define VM_DATA_DEFAULT_FLAGS \
	(VM_READ | VM_WRITE | \
	((current->personality & READ_IMPLIES_EXEC) ? VM_EXEC : 0 ) | \
		 VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)

#include <asm-generic/memory_model.h>
#include <asm-generic/page.h>

#define __HAVE_ARCH_GATE_AREA 1
#endif /* __KERNEL__ */

#endif /* _I386_PAGE_H */
