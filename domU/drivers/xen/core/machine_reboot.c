#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/reboot.h>
#include <linux/sysrq.h>
#include <linux/stringify.h>
#include <linux/stop_machine.h>
#include <asm/irq.h>
#include <asm/mmu_context.h>
#include <xen/evtchn.h>
#include <asm/hypervisor.h>
#include <xen/xenbus.h>
#include <linux/cpu.h>
#include <xen/gnttab.h>
#include <xen/xencons.h>
#include <xen/cpu_hotplug.h>
#include <xen/interface/vcpu.h>

/* The original dom id on slave, -1 if on master */
int HA_dom_id = -1;
/* Whether this is the first time resume on slave */
int HA_first_time;
int HA_suspend_evtchn = -1;
int HA_suspend_irq = -1;
int HA_xencons_evtchn = -1;
int HA_xencons_irq = -1;
int HA_xenbus_evtchn = -1;
int HA_fast_evtchn = -1;
int HA_fast_irq = -1;
int HA_fast_vbd_evtchn = -1;
int HA_fast_vbd_irq = -1;
int HA_xenbus_irq = -1;
int HA_have_check = 0;
int HA_block_xmit = 0;

extern unsigned long long sched_clock(void);
unsigned long get_ms(void)
{
	return sched_clock() / 1000000;
}

static int is_slave(void)
{
	return HYPERVISOR_which_side_op(0);
}

static void dump_evtch2irq(void)
{
	pr_debug("type\t\tevtchn\tirq\n");
	pr_debug("suspend\t\t%d\t%d\n", HA_suspend_evtchn, HA_suspend_irq);
	pr_debug("xencons\t\t%d\t%d\n", HA_xencons_evtchn, HA_xencons_irq);
	pr_debug("xenbus\t\t%d\t%d\n", HA_xenbus_evtchn, HA_xenbus_irq);
	pr_debug("vnif\t\t%d\t%d\n", HA_fast_evtchn, HA_fast_irq);
	pr_debug("vbd\t\t%d\t%d\n", HA_fast_vbd_evtchn, HA_fast_vbd_irq);
}

static void reset_evtchns(void)
{
	struct evtchn_select_reset evtrt;

	evtrt.port_no[0] = HA_suspend_evtchn;
	evtrt.port_no[1] = HA_xencons_evtchn;
	evtrt.port_no[2] = HA_xenbus_evtchn;
	evtrt.port_no[3] = HA_fast_evtchn;
	evtrt.port_no[4] = HA_fast_vbd_evtchn;
	evtrt.len = 5;

	if (HYPERVISOR_event_channel_op(EVTCHNOP_select_reset, &evtrt) != 0)
		printk(KERN_ERR "evtchn reset error!\n");
}

#if defined(__i386__) || defined(__x86_64__)

/*
 * Power off function, if any
 */
void (*pm_power_off)(void);
EXPORT_SYMBOL(pm_power_off);

void machine_emergency_restart(void)
{
	/* We really want to get pending console data out before we die. */
	xencons_force_flush();
	HYPERVISOR_shutdown(SHUTDOWN_reboot);
}

void machine_restart(char * __unused)
{
	machine_emergency_restart();
}

void machine_halt(void)
{
	machine_power_off();
}

void machine_power_off(void)
{
	/* We really want to get pending console data out before we die. */
	xencons_force_flush();
	if (pm_power_off)
		pm_power_off();
	HYPERVISOR_shutdown(SHUTDOWN_poweroff);
}

static void pre_suspend(void)
{
	HYPERVISOR_shared_info = (shared_info_t *)empty_zero_page;
	WARN_ON(HYPERVISOR_update_va_mapping(fix_to_virt(FIX_SHARED_INFO),
					     __pte_ma(0), 0));

	xen_start_info->store_mfn = mfn_to_pfn(xen_start_info->store_mfn);
	xen_start_info->console.domU.mfn =
		mfn_to_pfn(xen_start_info->console.domU.mfn);
}

static void post_suspend(int suspend_cancelled)
{
	int i, j, k, fpp;
	unsigned long shinfo_mfn;
	extern unsigned long max_pfn;
	extern unsigned long *pfn_to_mfn_frame_list_list;
	extern unsigned long *pfn_to_mfn_frame_list[];

	if (suspend_cancelled) {
		xen_start_info->store_mfn =
			pfn_to_mfn(xen_start_info->store_mfn);
		xen_start_info->console.domU.mfn =
			pfn_to_mfn(xen_start_info->console.domU.mfn);
	} else {
#ifdef CONFIG_SMP
		cpu_initialized_map = cpu_online_map;
#endif
	}

	shinfo_mfn = xen_start_info->shared_info >> PAGE_SHIFT;
	if (HYPERVISOR_update_va_mapping(fix_to_virt(FIX_SHARED_INFO),
					 pfn_pte_ma(shinfo_mfn, PAGE_KERNEL),
					 0))
		BUG();
	HYPERVISOR_shared_info = (shared_info_t *)fix_to_virt(FIX_SHARED_INFO);

	memset(empty_zero_page, 0, PAGE_SIZE);

	fpp = PAGE_SIZE/sizeof(unsigned long);
	for (i = 0, j = 0, k = -1; i < max_pfn; i += fpp, j++) {
		if ((j % fpp) == 0) {
			k++;
			pfn_to_mfn_frame_list_list[k] =
				virt_to_mfn(pfn_to_mfn_frame_list[k]);
			j = 0;
		}
		pfn_to_mfn_frame_list[k][j] =
			virt_to_mfn(&phys_to_machine_mapping[i]);
	}
	HYPERVISOR_shared_info->arch.max_pfn = max_pfn;
	HYPERVISOR_shared_info->arch.pfn_to_mfn_frame_list_list =
		virt_to_mfn(pfn_to_mfn_frame_list_list);
}

#else /* !(defined(__i386__) || defined(__x86_64__)) */

#ifndef HAVE_XEN_PRE_SUSPEND
#define xen_pre_suspend()	((void)0)
#endif

#ifndef HAVE_XEN_POST_SUSPEND
#define xen_post_suspend(x)	((void)0)
#endif

#define switch_idle_mm()	((void)0)
#define mm_pin_all()		((void)0)
#define pre_suspend()		xen_pre_suspend()
#define post_suspend(x)		xen_post_suspend(x)

#endif

struct suspend {
	int fast_suspend;
	void (*resume_notifier)(int);
};

static int take_machine_down(void *_suspend)
{
	struct suspend *suspend = _suspend;
	int suspend_cancelled, err;
	extern void time_resume(void);

	if (suspend->fast_suspend) {
		BUG_ON(!irqs_disabled());
	} else {
		BUG_ON(irqs_disabled());

		for (;;) {
			err = smp_suspend();
			if (err)
				return err;

			xenbus_suspend();
			preempt_disable();

			if (num_online_cpus() == 1)
				break;

			preempt_enable();
			xenbus_suspend_cancel();
		}

		local_irq_disable();
	}

	mm_pin_all();
	gnttab_suspend();

	/* Only slave side should reset all event channels. */
	dump_evtch2irq();
	if (HA_dom_id > 0) {
		reset_evtchns();
		pr_info("[%lums]yewei: reset event channels done.\n", get_ms());
	}
	pr_info("yewei: xenbus event: channel=%d, irq=%d.\n", HA_xenbus_evtchn,
		HA_xenbus_irq);

	pre_suspend();

	/*
	 * This hypercall returns 1 if suspend was cancelled or the domain was
	 * merely checkpointed, and 0 if it is resuming in a new domain.
	 */
	suspend_cancelled = HYPERVISOR_suspend(virt_to_mfn(xen_start_info));
	if (HA_have_check < 2)
		HA_have_check++;

	// -1 if on master, otherwise return the dom id
	HA_dom_id = is_slave();
	if ( HA_dom_id > 0 )
		/* slave side */
		HA_first_time = (suspend_cancelled == 0);
	pr_info("yewei: HA_dom_id=%d, HA_first_time=%d\n", HA_dom_id,
		HA_first_time);
	pr_info("yewei: xenbus event: channel=%d, irq=%d.\n", HA_xenbus_evtchn,
		HA_xenbus_irq);

	suspend->resume_notifier(suspend_cancelled);
	post_suspend(HA_dom_id > 0 ? 0 : suspend_cancelled);
	gnttab_resume();
	if (!suspend_cancelled || HA_dom_id > 0) {
		pr_info("[%lums]yewei: irq_resume...\n", get_ms());
		irq_resume();
		pr_info("[%lums]yewei: irq_resume done\n", get_ms());
#ifdef __x86_64__
		/*
		 * Older versions of Xen do not save/restore the user %cr3.
		 * We do it here just in case, but there's no need if we are
		 * in fast-suspend mode as that implies a new enough Xen.
		 */
		if (!suspend->fast_suspend)
			xen_new_user_pt(__pa(__user_pgd(
				current->active_mm->pgd)));
#endif
	}
	time_resume();

	if (!suspend->fast_suspend)
		local_irq_enable();

	return suspend_cancelled;
}

int __xen_suspend(int fast_suspend, void (*resume_notifier)(int))
{
	int err, suspend_cancelled;
	struct suspend suspend;

	BUG_ON(smp_processor_id() != 0);
	BUG_ON(in_interrupt());

#if defined(__i386__) || defined(__x86_64__)
	if (xen_feature(XENFEAT_auto_translated_physmap)) {
		printk(KERN_WARNING "Cannot suspend in "
		       "auto_translated_physmap mode.\n");
		return -EOPNOTSUPP;
	}
#endif

	printk(KERN_NOTICE "\n\n=============checkpoint===============.\n");

	/* If we are definitely UP then 'slow mode' is actually faster. */
	if (num_possible_cpus() == 1)
		fast_suspend = 0;

	suspend.fast_suspend = fast_suspend;
	suspend.resume_notifier = resume_notifier;

	HA_block_xmit = 1;
	pr_info("[%lums]fb_disconnect begin.\n", get_ms());
	fb_disconnect();
	pr_info("[%lums]fb_disconnect end.\n", get_ms());
	if (fast_suspend) {
		xenbus_suspend();
		err = stop_machine_run(take_machine_down, &suspend, 0);
		if (err < 0)
			xenbus_suspend_cancel();
	} else {
		err = take_machine_down(&suspend);
	}

	if (err < 0)
		return err;

	pr_info("[%lums]yewei: return from take machine down.\n", get_ms());
	suspend_cancelled = err;
	if (!suspend_cancelled) {
		xencons_resume();
		xenbus_resume();
	} else if (suspend_cancelled == 1) {
		xs_suspend_cancel();
		pr_info("[%lu]fb_connect begin\n", get_ms());
		fb_connect();
		pr_info("[%lu]fb_connect end\n", get_ms());
	} else {
		/* second and later checkpoint on slave */
		xs_resume();
		pr_info("[%lums]yewei: fb connect begin.\n", get_ms());
		fb_connect();
		pr_info("[%lums]yewei: fb connect end.\n", get_ms());
	}

	if (!fast_suspend)
		smp_resume();

	return 0;
}
