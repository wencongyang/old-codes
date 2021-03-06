/*
 * Copyright (C) 2006 Hollis Blanchard <hollisb@us.ibm.com>, IBM Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <linux/gfp.h>
#include <linux/mm.h>
#include <xen/interface/xen.h>
#include <asm/page.h>

#ifdef HAVE_XEN_PLATFORM_COMPAT_H
#include <xen/platform-compat.h>
#endif

#include <asm/xen/xencomm.h>

static unsigned long kernel_start_pa;

void
xencomm_initialize (void)
{
	kernel_start_pa = KERNEL_START - ia64_tpa(KERNEL_START);
}

/* Translate virtual address to physical address.  */
unsigned long
xencomm_vtop(unsigned long vaddr)
{
#ifndef CONFIG_VMX_GUEST
	struct page *page;
	struct vm_area_struct *vma;
#endif

	if (vaddr == 0)
		return 0;

#ifdef __ia64__
	if (REGION_NUMBER(vaddr) == 5) {
		pgd_t *pgd;
		pud_t *pud;
		pmd_t *pmd;
		pte_t *ptep;

		/* On ia64, TASK_SIZE refers to current.  It is not initialized
		   during boot.
		   Furthermore the kernel is relocatable and __pa() doesn't
		   work on  addresses.  */
		if (vaddr >= KERNEL_START
		    && vaddr < (KERNEL_START + KERNEL_TR_PAGE_SIZE)) {
			return vaddr - kernel_start_pa;
		}

		/* In kernel area -- virtually mapped.  */
		pgd = pgd_offset_k(vaddr);
		if (pgd_none(*pgd) || pgd_bad(*pgd))
			return ~0UL;

		pud = pud_offset(pgd, vaddr);
		if (pud_none(*pud) || pud_bad(*pud))
			return ~0UL;

		pmd = pmd_offset(pud, vaddr);
		if (pmd_none(*pmd) || pmd_bad(*pmd))
			return ~0UL;

		ptep = pte_offset_kernel(pmd, vaddr);
		if (!ptep)
			return ~0UL;

		return (pte_val(*ptep) & _PFN_MASK) | (vaddr & ~PAGE_MASK);
	}
#endif

	if (vaddr > TASK_SIZE) {
		/* kernel address */
		return __pa(vaddr);
	}


#ifdef CONFIG_VMX_GUEST
	/* No privcmd within vmx guest.  */
	return ~0UL;
#else
	/* XXX double-check (lack of) locking */
	vma = find_extend_vma(current->mm, vaddr);
	if (!vma)
		return ~0UL;

	/* We assume the page is modified.  */
	page = follow_page(vma, vaddr, FOLL_WRITE | FOLL_TOUCH);
	if (!page)
		return ~0UL;

	return (page_to_pfn(page) << PAGE_SHIFT) | (vaddr & ~PAGE_MASK);
#endif
}
