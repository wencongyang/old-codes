/* 
 * Copyright 2002 Andi Kleen, SuSE Labs. 
 * Thanks to Ben LaHaise for precious feedback.
 */ 

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <asm/processor.h>
#include <asm/tlbflush.h>
#include <asm/io.h>

#ifdef CONFIG_XEN
#include <asm/pgalloc.h>
#include <asm/mmu_context.h>

LIST_HEAD(mm_unpinned);
DEFINE_SPINLOCK(mm_unpinned_lock);

static void _pin_lock(struct mm_struct *mm, int lock) {
	if (lock)
		spin_lock(&mm->page_table_lock);
#if NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS
	/* While mm->page_table_lock protects us against insertions and
	 * removals of higher level page table pages, it doesn't protect
	 * against updates of pte-s. Such updates, however, require the
	 * pte pages to be in consistent state (unpinned+writable or
	 * pinned+readonly). The pinning and attribute changes, however
	 * cannot be done atomically, which is why such updates must be
	 * prevented from happening concurrently.
	 * Note that no pte lock can ever elsewhere be acquired nesting
	 * with an already acquired one in the same mm, or with the mm's
	 * page_table_lock already acquired, as that would break in the
	 * non-split case (where all these are actually resolving to the
	 * one page_table_lock). Thus acquiring all of them here is not
	 * going to result in dead locks, and the order of acquires
	 * doesn't matter.
	 */
	{
		pgd_t *pgd = mm->pgd;
		unsigned g;

		for (g = 0; g <= ((TASK_SIZE64-1) / PGDIR_SIZE); g++, pgd++) {
			pud_t *pud;
			unsigned u;

			if (pgd_none(*pgd))
				continue;
			pud = pud_offset(pgd, 0);
			for (u = 0; u < PTRS_PER_PUD; u++, pud++) {
				pmd_t *pmd;
				unsigned m;

				if (pud_none(*pud))
					continue;
				pmd = pmd_offset(pud, 0);
				for (m = 0; m < PTRS_PER_PMD; m++, pmd++) {
					spinlock_t *ptl;

					if (pmd_none(*pmd))
						continue;
					ptl = pte_lockptr(0, pmd);
					if (lock)
						spin_lock(ptl);
					else
						spin_unlock(ptl);
				}
			}
		}
	}
#endif
	if (!lock)
		spin_unlock(&mm->page_table_lock);
}
#define pin_lock(mm) _pin_lock(mm, 1)
#define pin_unlock(mm) _pin_lock(mm, 0)

#define PIN_BATCH 8
static DEFINE_PER_CPU(multicall_entry_t[PIN_BATCH], pb_mcl);

static inline unsigned int mm_walk_set_prot(void *pt, pgprot_t flags,
                                            unsigned int cpu, unsigned int seq)
{
	struct page *page = virt_to_page(pt);
	unsigned long pfn = page_to_pfn(page);

	MULTI_update_va_mapping(per_cpu(pb_mcl, cpu) + seq,
		(unsigned long)__va(pfn << PAGE_SHIFT),
		pfn_pte(pfn, flags), 0);
	if (unlikely(++seq == PIN_BATCH)) {
		if (unlikely(HYPERVISOR_multicall_check(per_cpu(pb_mcl, cpu),
	                                                PIN_BATCH, NULL)))
			BUG();
		seq = 0;
	}

	return seq;
}

static void mm_walk(struct mm_struct *mm, pgprot_t flags)
{
	pgd_t       *pgd;
	pud_t       *pud;
	pmd_t       *pmd;
	pte_t       *pte;
	int          g,u,m;
	unsigned int cpu, seq;
	multicall_entry_t *mcl;

	pgd = mm->pgd;
	cpu = get_cpu();

	/*
	 * Cannot iterate up to USER_PTRS_PER_PGD as these pagetables may not
	 * be the 'current' task's pagetables (e.g., current may be 32-bit,
	 * but the pagetables may be for a 64-bit task).
	 * Subtracting 1 from TASK_SIZE64 means the loop limit is correct
	 * regardless of whether TASK_SIZE64 is a multiple of PGDIR_SIZE.
	 */
	for (g = 0, seq = 0; g <= ((TASK_SIZE64-1) / PGDIR_SIZE); g++, pgd++) {
		if (pgd_none(*pgd))
			continue;
		pud = pud_offset(pgd, 0);
		if (PTRS_PER_PUD > 1) /* not folded */ 
			seq = mm_walk_set_prot(pud,flags,cpu,seq);
		for (u = 0; u < PTRS_PER_PUD; u++, pud++) {
			if (pud_none(*pud))
				continue;
			pmd = pmd_offset(pud, 0);
			if (PTRS_PER_PMD > 1) /* not folded */ 
				seq = mm_walk_set_prot(pmd,flags,cpu,seq);
			for (m = 0; m < PTRS_PER_PMD; m++, pmd++) {
				if (pmd_none(*pmd))
					continue;
				pte = pte_offset_kernel(pmd,0);
				seq = mm_walk_set_prot(pte,flags,cpu,seq);
			}
		}
	}

	mcl = per_cpu(pb_mcl, cpu);
	if (unlikely(seq > PIN_BATCH - 2)) {
		if (unlikely(HYPERVISOR_multicall_check(mcl, seq, NULL)))
			BUG();
		seq = 0;
	}
	MULTI_update_va_mapping(mcl + seq,
	       (unsigned long)__user_pgd(mm->pgd),
	       pfn_pte(virt_to_phys(__user_pgd(mm->pgd))>>PAGE_SHIFT, flags),
	       0);
	MULTI_update_va_mapping(mcl + seq + 1,
	       (unsigned long)mm->pgd,
	       pfn_pte(virt_to_phys(mm->pgd)>>PAGE_SHIFT, flags),
	       UVMF_TLB_FLUSH);
	if (unlikely(HYPERVISOR_multicall_check(mcl, seq + 2, NULL)))
		BUG();

	put_cpu();
}

void mm_pin(struct mm_struct *mm)
{
	if (xen_feature(XENFEAT_writable_page_tables))
		return;

	pin_lock(mm);

	mm_walk(mm, PAGE_KERNEL_RO);
	xen_pgd_pin(__pa(mm->pgd)); /* kernel */
	xen_pgd_pin(__pa(__user_pgd(mm->pgd))); /* user */
	mm->context.pinned = 1;
	spin_lock(&mm_unpinned_lock);
	list_del(&mm->context.unpinned);
	spin_unlock(&mm_unpinned_lock);

	pin_unlock(mm);
}

void mm_unpin(struct mm_struct *mm)
{
	if (xen_feature(XENFEAT_writable_page_tables))
		return;

	pin_lock(mm);

	xen_pgd_unpin(__pa(mm->pgd));
	xen_pgd_unpin(__pa(__user_pgd(mm->pgd)));
	mm_walk(mm, PAGE_KERNEL);
	mm->context.pinned = 0;
	spin_lock(&mm_unpinned_lock);
	list_add(&mm->context.unpinned, &mm_unpinned);
	spin_unlock(&mm_unpinned_lock);

	pin_unlock(mm);
}

void mm_pin_all(void)
{
	if (xen_feature(XENFEAT_writable_page_tables))
		return;

	/*
	 * Allow uninterrupted access to the mm_unpinned list. We don't
	 * actually take the mm_unpinned_lock as it is taken inside mm_pin().
	 * All other CPUs must be at a safe point (e.g., in stop_machine
	 * or offlined entirely).
	 */
	preempt_disable();
	while (!list_empty(&mm_unpinned))	
		mm_pin(list_entry(mm_unpinned.next, struct mm_struct,
				  context.unpinned));
	preempt_enable();
}

void _arch_dup_mmap(struct mm_struct *mm)
{
	if (!mm->context.pinned)
		mm_pin(mm);
}

void _arch_exit_mmap(struct mm_struct *mm)
{
	struct task_struct *tsk = current;

	task_lock(tsk);

	/*
	 * We aggressively remove defunct pgd from cr3. We execute unmap_vmas()
	 * *much* faster this way, as no tlb flushes means bigger wrpt batches.
	 */
	if (tsk->active_mm == mm) {
		tsk->active_mm = &init_mm;
		atomic_inc(&init_mm.mm_count);

		switch_mm(mm, &init_mm, tsk);

		atomic_dec(&mm->mm_count);
		BUG_ON(atomic_read(&mm->mm_count) == 0);
	}

	task_unlock(tsk);

	if ( mm->context.pinned && (atomic_read(&mm->mm_count) == 1) &&
	     !mm->context.has_foreign_mappings )
		mm_unpin(mm);
}

static void _pte_free(struct page *page, unsigned int order)
{
	BUG_ON(order);
	pte_free(page);
}

struct page *pte_alloc_one(struct mm_struct *mm, unsigned long address)
{
	struct page *pte;

	pte = alloc_pages(GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO, 0);
	if (pte) {
		SetPageForeign(pte, _pte_free);
		init_page_count(pte);
	}
	return pte;
}

void pte_free(struct page *pte)
{
	unsigned long va = (unsigned long)__va(page_to_pfn(pte)<<PAGE_SHIFT);

	if (!pte_write(*virt_to_ptep(va)))
		if (HYPERVISOR_update_va_mapping(
			va, pfn_pte(page_to_pfn(pte), PAGE_KERNEL), 0))
			BUG();

	ClearPageForeign(pte);
	init_page_count(pte);

	__free_page(pte);
}
#endif	/* CONFIG_XEN */

pte_t *lookup_address(unsigned long address) 
{ 
	pgd_t *pgd = pgd_offset_k(address);
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	if (pgd_none(*pgd))
		return NULL;
	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		return NULL; 
	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		return NULL; 
	if (pmd_large(*pmd))
		return (pte_t *)pmd;
	pte = pte_offset_kernel(pmd, address);
	if (pte && !pte_present(*pte))
		pte = NULL; 
	return pte;
} 

static struct page *split_large_page(unsigned long address, pgprot_t prot,
				     pgprot_t ref_prot)
{ 
	int i; 
	unsigned long addr;
	struct page *base = alloc_pages(GFP_KERNEL, 0);
	pte_t *pbase;
	if (!base) 
		return NULL;
	/*
	 * page_private is used to track the number of entries in
	 * the page table page have non standard attributes.
	 */
	SetPagePrivate(base);
	page_private(base) = 0;

	address = __pa(address);
	addr = address & LARGE_PAGE_MASK; 
	pbase = (pte_t *)page_address(base);
	for (i = 0; i < PTRS_PER_PTE; i++, addr += PAGE_SIZE) {
		pbase[i] = pfn_pte(addr >> PAGE_SHIFT, 
				   addr == address ? prot : ref_prot);
	}
	return base;
} 


static void flush_kernel_map(void *address) 
{
	if (0 && address && cpu_has_clflush) {
		/* is this worth it? */ 
		int i;
		for (i = 0; i < PAGE_SIZE; i += boot_cpu_data.x86_clflush_size) 
			asm volatile("clflush (%0)" :: "r" (address + i)); 
	} else
		asm volatile("wbinvd":::"memory"); 
	if (address)
		__flush_tlb_one(address);
	else
		__flush_tlb_all();
}


static inline void flush_map(unsigned long address)
{	
	on_each_cpu(flush_kernel_map, (void *)address, 1, 1);
}

static struct page *deferred_pages; /* protected by init_mm.mmap_sem */

static inline void save_page(struct page *fpage)
{
	fpage->lru.next = (struct list_head *)deferred_pages;
	deferred_pages = fpage;
}

/* 
 * No more special protections in this 2/4MB area - revert to a
 * large page again. 
 */
static void revert_page(unsigned long address, pgprot_t ref_prot)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t large_pte;

	pgd = pgd_offset_k(address);
	BUG_ON(pgd_none(*pgd));
	pud = pud_offset(pgd,address);
	BUG_ON(pud_none(*pud));
	pmd = pmd_offset(pud, address);
	BUG_ON(__pmd_val(*pmd) & _PAGE_PSE);
	pgprot_val(ref_prot) |= _PAGE_PSE;
	large_pte = mk_pte_phys(__pa(address) & LARGE_PAGE_MASK, ref_prot);
	set_pte((pte_t *)pmd, large_pte);
}      

static int
__change_page_attr(unsigned long address, unsigned long pfn, pgprot_t prot,
				   pgprot_t ref_prot)
{ 
	pte_t *kpte; 
	struct page *kpte_page;
	unsigned kpte_flags;
	pgprot_t ref_prot2;
	kpte = lookup_address(address);
	if (!kpte) return 0;
	kpte_page = virt_to_page(((unsigned long)kpte) & PAGE_MASK);
	kpte_flags = pte_val(*kpte); 
	if (pgprot_val(prot) != pgprot_val(ref_prot)) { 
		if ((kpte_flags & _PAGE_PSE) == 0) { 
			set_pte(kpte, pfn_pte(pfn, prot));
		} else {
 			/*
			 * split_large_page will take the reference for this
			 * change_page_attr on the split page.
 			 */

			struct page *split;
			ref_prot2 = __pgprot(pgprot_val(pte_pgprot(*lookup_address(address))) & ~(1<<_PAGE_BIT_PSE));

			split = split_large_page(address, prot, ref_prot2);
			if (!split)
				return -ENOMEM;
			set_pte(kpte,mk_pte(split, ref_prot2));
			kpte_page = split;
		}	
		page_private(kpte_page)++;
	} else if ((kpte_flags & _PAGE_PSE) == 0) { 
		set_pte(kpte, pfn_pte(pfn, ref_prot));
		BUG_ON(page_private(kpte_page) == 0);
		page_private(kpte_page)--;
	} else
		BUG();

	/* on x86-64 the direct mapping set at boot is not using 4k pages */
	/*
	 * ..., but the XEN guest kernels (currently) do:
	 * If the pte was reserved, it means it was created at boot
	 * time (not via split_large_page) and in turn we must not
	 * replace it with a large page.
	 */
#ifndef CONFIG_XEN
 	BUG_ON(PageReserved(kpte_page));
#else
	if (PageReserved(kpte_page))
		return 0;
#endif

	if (page_private(kpte_page) == 0) {
		save_page(kpte_page);
		revert_page(address, ref_prot);
	}
	return 0;
} 

/*
 * Change the page attributes of an page in the linear mapping.
 *
 * This should be used when a page is mapped with a different caching policy
 * than write-back somewhere - some CPUs do not like it when mappings with
 * different caching policies exist. This changes the page attributes of the
 * in kernel linear mapping too.
 * 
 * The caller needs to ensure that there are no conflicting mappings elsewhere.
 * This function only deals with the kernel linear map.
 * 
 * Caller must call global_flush_tlb() after this.
 */
int change_page_attr_addr(unsigned long address, int numpages, pgprot_t prot)
{
	int err = 0; 
	int i; 

	down_write(&init_mm.mmap_sem);
	for (i = 0; i < numpages; i++, address += PAGE_SIZE) {
		unsigned long pfn = __pa(address) >> PAGE_SHIFT;

		err = __change_page_attr(address, pfn, prot, PAGE_KERNEL);
		if (err) 
			break; 
		/* Handle kernel mapping too which aliases part of the
		 * lowmem */
		if (__pa(address) < KERNEL_TEXT_SIZE) {
			unsigned long addr2;
			pgprot_t prot2 = prot;
			addr2 = __START_KERNEL_map + __pa(address);
 			pgprot_val(prot2) &= ~_PAGE_NX;
			err = __change_page_attr(addr2, pfn, prot2, PAGE_KERNEL_EXEC);
		} 
	} 	
	up_write(&init_mm.mmap_sem); 
	return err;
}

/* Don't call this for MMIO areas that may not have a mem_map entry */
int change_page_attr(struct page *page, int numpages, pgprot_t prot)
{
	unsigned long addr = (unsigned long)page_address(page);
	return change_page_attr_addr(addr, numpages, prot);
}

void global_flush_tlb(void)
{ 
	struct page *dpage;

	down_read(&init_mm.mmap_sem);
	dpage = xchg(&deferred_pages, NULL);
	up_read(&init_mm.mmap_sem);

	flush_map((dpage && !dpage->lru.next) ? (unsigned long)page_address(dpage) : 0);
	while (dpage) {
		struct page *tmp = dpage;
		dpage = (struct page *)dpage->lru.next;
		ClearPagePrivate(tmp);
		__free_page(tmp);
	} 
} 

EXPORT_SYMBOL(change_page_attr);
EXPORT_SYMBOL(global_flush_tlb);
