/******************************************************************************
 * hypervisor.h
 * 
 * Linux-specific hypervisor handling.
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

#ifndef __HYPERVISOR_H__
#define __HYPERVISOR_H__

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <xen/interface/xen.h>
#include <xen/interface/platform.h>
#include <xen/interface/event_channel.h>
#include <xen/interface/physdev.h>
#include <xen/interface/sched.h>
#include <xen/interface/nmi.h>
#include <xen/interface/tmem.h>
#include <asm/ptrace.h>
#include <asm/page.h>
#if defined(__i386__)
#  ifdef CONFIG_X86_PAE
#   include <asm-generic/pgtable-nopud.h>
#  else
#   include <asm-generic/pgtable-nopmd.h>
#  endif
#elif defined(__x86_64__) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
#  include <asm-generic/pgtable-nopud.h>
#endif

extern shared_info_t *HYPERVISOR_shared_info;

#define vcpu_info(cpu) (HYPERVISOR_shared_info->vcpu_info + (cpu))
#ifdef CONFIG_SMP
#define current_vcpu_info() vcpu_info(smp_processor_id())
#else
#define current_vcpu_info() vcpu_info(0)
#endif

#ifdef CONFIG_X86_32
extern unsigned long hypervisor_virt_start;
#endif

/* arch/xen/i386/kernel/setup.c */
extern start_info_t *xen_start_info;
#ifdef CONFIG_XEN_PRIVILEGED_GUEST
#define is_initial_xendomain() (xen_start_info->flags & SIF_INITDOMAIN)
#else
#define is_initial_xendomain() 0
#endif

/* arch/xen/kernel/evtchn.c */
/* Force a proper event-channel callback from Xen. */
void force_evtchn_callback(void);

/* arch/xen/kernel/process.c */
void xen_cpu_idle (void);

/* arch/xen/i386/kernel/hypervisor.c */
void do_hypervisor_callback(struct pt_regs *regs);

/* arch/xen/i386/mm/hypervisor.c */
/*
 * NB. ptr values should be PHYSICAL, not MACHINE. 'vals' should be already
 * be MACHINE addresses.
 */

void xen_pt_switch(unsigned long ptr);
void xen_new_user_pt(unsigned long ptr); /* x86_64 only */
void xen_load_gs(unsigned int selector); /* x86_64 only */
void xen_tlb_flush(void);
void xen_invlpg(unsigned long ptr);

void xen_l1_entry_update(pte_t *ptr, pte_t val);
void xen_l2_entry_update(pmd_t *ptr, pmd_t val);
void xen_l3_entry_update(pud_t *ptr, pud_t val); /* x86_64/PAE */
void xen_l4_entry_update(pgd_t *ptr, pgd_t val); /* x86_64 only */
void xen_pgd_pin(unsigned long ptr);
void xen_pgd_unpin(unsigned long ptr);

void xen_set_ldt(const void *ptr, unsigned int ents);

#ifdef CONFIG_SMP
#include <linux/cpumask.h>
void xen_tlb_flush_all(void);
void xen_invlpg_all(unsigned long ptr);
void xen_tlb_flush_mask(cpumask_t *mask);
void xen_invlpg_mask(cpumask_t *mask, unsigned long ptr);
#else
#define xen_tlb_flush_all xen_tlb_flush
#define xen_invlpg_all xen_invlpg
#endif

/* Returns zero on success else negative errno. */
int xen_create_contiguous_region(
    unsigned long vstart, unsigned int order, unsigned int address_bits);
void xen_destroy_contiguous_region(
    unsigned long vstart, unsigned int order);

struct page;

int xen_limit_pages_to_max_mfn(
	struct page *pages, unsigned int order, unsigned int address_bits);

/* Turn jiffies into Xen system time. */
u64 jiffies_to_st(unsigned long jiffies);

#ifdef CONFIG_XEN_SCRUB_PAGES
void scrub_pages(void *, unsigned int);
#else
#define scrub_pages(_p,_n) ((void)0)
#endif

#include <xen/hypercall.h>

#if defined(CONFIG_X86_64)
#define MULTI_UVMFLAGS_INDEX 2
#define MULTI_UVMDOMID_INDEX 3
#else
#define MULTI_UVMFLAGS_INDEX 3
#define MULTI_UVMDOMID_INDEX 4
#endif

#ifdef CONFIG_XEN
#define is_running_on_xen() 1
#else
extern char *hypercall_stubs;
#define is_running_on_xen() (!!hypercall_stubs)
#endif

static inline int
HYPERVISOR_yield(
	void)
{
	int rc = HYPERVISOR_sched_op(SCHEDOP_yield, NULL);

#if CONFIG_XEN_COMPAT <= 0x030002
	if (rc == -ENOSYS)
		rc = HYPERVISOR_sched_op_compat(SCHEDOP_yield, 0);
#endif

	return rc;
}

static inline int
HYPERVISOR_block(
	void)
{
	int rc = HYPERVISOR_sched_op(SCHEDOP_block, NULL);

#if CONFIG_XEN_COMPAT <= 0x030002
	if (rc == -ENOSYS)
		rc = HYPERVISOR_sched_op_compat(SCHEDOP_block, 0);
#endif

	return rc;
}

static inline void /*__noreturn*/
HYPERVISOR_shutdown(
	unsigned int reason)
{
	struct sched_shutdown sched_shutdown = {
		.reason = reason
	};

	VOID(HYPERVISOR_sched_op(SCHEDOP_shutdown, &sched_shutdown));
#if CONFIG_XEN_COMPAT <= 0x030002
	VOID(HYPERVISOR_sched_op_compat(SCHEDOP_shutdown, reason));
#endif
	/* Don't recurse needlessly. */
	BUG_ON(reason != SHUTDOWN_crash);
	for(;;);
}

static inline int __must_check
HYPERVISOR_poll(
	evtchn_port_t *ports, unsigned int nr_ports, u64 timeout)
{
	int rc;
	struct sched_poll sched_poll = {
		.nr_ports = nr_ports,
		.timeout = jiffies_to_st(timeout)
	};
	set_xen_guest_handle(sched_poll.ports, ports);

	rc = HYPERVISOR_sched_op(SCHEDOP_poll, &sched_poll);
#if CONFIG_XEN_COMPAT <= 0x030002
	if (rc == -ENOSYS)
		rc = HYPERVISOR_sched_op_compat(SCHEDOP_yield, 0);
#endif

	return rc;
}

#ifdef CONFIG_XEN

static inline void
MULTI_update_va_mapping(
    multicall_entry_t *mcl, unsigned long va,
    pte_t new_val, unsigned long flags)
{
    mcl->op = __HYPERVISOR_update_va_mapping;
    mcl->args[0] = va;
#if defined(CONFIG_X86_64)
    mcl->args[1] = new_val.pte;
#elif defined(CONFIG_X86_PAE)
    mcl->args[1] = new_val.pte_low;
    mcl->args[2] = new_val.pte_high;
#else
    mcl->args[1] = new_val.pte_low;
    mcl->args[2] = 0;
#endif
    mcl->args[MULTI_UVMFLAGS_INDEX] = flags;
}

static inline void
MULTI_grant_table_op(multicall_entry_t *mcl, unsigned int cmd,
		     void *uop, unsigned int count)
{
    mcl->op = __HYPERVISOR_grant_table_op;
    mcl->args[0] = cmd;
    mcl->args[1] = (unsigned long)uop;
    mcl->args[2] = count;
}

#else /* !defined(CONFIG_XEN) */

/* Multicalls not supported for HVM guests. */
#define MULTI_update_va_mapping(a,b,c,d) ((void)0)
#define MULTI_grant_table_op(a,b,c,d) ((void)0)

#endif

#endif /* __HYPERVISOR_H__ */
