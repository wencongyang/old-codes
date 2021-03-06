/*
 *	Xen SMP booting functions
 *
 *	See arch/i386/kernel/smpboot.c for copyright and credits for derived
 *	portions of this file.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/smp_lock.h>
#include <linux/irq.h>
#include <linux/bootmem.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/percpu.h>
#include <asm/desc.h>
#include <asm/arch_hooks.h>
#include <asm/pgalloc.h>
#include <xen/evtchn.h>
#include <xen/interface/vcpu.h>
#include <xen/cpu_hotplug.h>
#include <xen/xenbus.h>

extern irqreturn_t smp_reschedule_interrupt(int, void *, struct pt_regs *);
extern irqreturn_t smp_call_function_interrupt(int, void *, struct pt_regs *);

extern int local_setup_timer(unsigned int cpu);
extern void local_teardown_timer(unsigned int cpu);

extern void hypervisor_callback(void);
extern void failsafe_callback(void);
extern void system_call(void);
extern void smp_trap_init(trap_info_t *);

/* Number of siblings per CPU package */
int smp_num_siblings = 1;

cpumask_t cpu_online_map;
EXPORT_SYMBOL(cpu_online_map);
cpumask_t cpu_possible_map;
EXPORT_SYMBOL(cpu_possible_map);
cpumask_t cpu_initialized_map;

struct cpuinfo_x86 cpu_data[NR_CPUS] __cacheline_aligned;
EXPORT_SYMBOL(cpu_data);

static DEFINE_PER_CPU(int, resched_irq);
static DEFINE_PER_CPU(int, callfunc_irq);
static char resched_name[NR_CPUS][15];
static char callfunc_name[NR_CPUS][15];

cpumask_t cpu_sibling_map[NR_CPUS] __cacheline_aligned;
cpumask_t cpu_core_map[NR_CPUS] __cacheline_aligned;
EXPORT_SYMBOL(cpu_core_map);

#if defined(__i386__)
u8 x86_cpu_to_apicid[NR_CPUS] = { [0 ... NR_CPUS-1] = 0xff };
EXPORT_SYMBOL(x86_cpu_to_apicid);
#elif !defined(CONFIG_X86_IO_APIC)
unsigned int maxcpus = NR_CPUS;
#endif

void __init prefill_possible_map(void)
{
	int i, rc;

	for_each_possible_cpu(i)
	    if (i != smp_processor_id())
		return;

	for (i = 0; i < NR_CPUS; i++) {
		rc = HYPERVISOR_vcpu_op(VCPUOP_is_up, i, NULL);
		if (rc >= 0)
			cpu_set(i, cpu_possible_map);
	}
}

void __init smp_alloc_memory(void)
{
}

static inline void
set_cpu_sibling_map(unsigned int cpu)
{
	cpu_data[cpu].phys_proc_id = cpu;
	cpu_data[cpu].cpu_core_id  = 0;

	cpu_sibling_map[cpu] = cpumask_of_cpu(cpu);
	cpu_core_map[cpu]    = cpumask_of_cpu(cpu);

	cpu_data[cpu].booted_cores = 1;
}

static void
remove_siblinginfo(unsigned int cpu)
{
	cpu_data[cpu].phys_proc_id = BAD_APICID;
	cpu_data[cpu].cpu_core_id  = BAD_APICID;

	cpus_clear(cpu_sibling_map[cpu]);
	cpus_clear(cpu_core_map[cpu]);

	cpu_data[cpu].booted_cores = 0;
}

static int __cpuinit xen_smp_intr_init(unsigned int cpu)
{
	int rc;

	per_cpu(resched_irq, cpu) = per_cpu(callfunc_irq, cpu) = -1;

	sprintf(resched_name[cpu], "resched%u", cpu);
	rc = bind_ipi_to_irqhandler(RESCHEDULE_VECTOR,
				    cpu,
				    smp_reschedule_interrupt,
				    SA_INTERRUPT,
				    resched_name[cpu],
				    NULL);
	if (rc < 0)
		goto fail;
	per_cpu(resched_irq, cpu) = rc;

	sprintf(callfunc_name[cpu], "callfunc%u", cpu);
	rc = bind_ipi_to_irqhandler(CALL_FUNCTION_VECTOR,
				    cpu,
				    smp_call_function_interrupt,
				    SA_INTERRUPT,
				    callfunc_name[cpu],
				    NULL);
	if (rc < 0)
		goto fail;
	per_cpu(callfunc_irq, cpu) = rc;

	if ((cpu != 0) && ((rc = local_setup_timer(cpu)) != 0))
		goto fail;

	return 0;

 fail:
	if (per_cpu(resched_irq, cpu) >= 0)
		unbind_from_irqhandler(per_cpu(resched_irq, cpu), NULL);
	if (per_cpu(callfunc_irq, cpu) >= 0)
		unbind_from_irqhandler(per_cpu(callfunc_irq, cpu), NULL);
	return rc;
}

#ifdef CONFIG_HOTPLUG_CPU
static void xen_smp_intr_exit(unsigned int cpu)
{
	if (cpu != 0)
		local_teardown_timer(cpu);

	unbind_from_irqhandler(per_cpu(resched_irq, cpu), NULL);
	unbind_from_irqhandler(per_cpu(callfunc_irq, cpu), NULL);
}
#endif

void __cpuinit cpu_bringup(void)
{
	cpu_init();
	identify_cpu(cpu_data + smp_processor_id());
	touch_softlockup_watchdog();
	preempt_disable();
	local_irq_enable();
}

static void __cpuinit cpu_bringup_and_idle(void)
{
	cpu_bringup();
	cpu_idle();
}

static void __cpuinit cpu_initialize_context(unsigned int cpu)
{
	/* vcpu_guest_context_t is too large to allocate on the stack.
	 * Hence we allocate statically and protect it with a lock */
	static vcpu_guest_context_t ctxt;
	static DEFINE_SPINLOCK(ctxt_lock);

	struct task_struct *idle = idle_task(cpu);
#ifdef __x86_64__
	struct desc_ptr *gdt_descr = &cpu_gdt_descr[cpu];
#else
	struct Xgt_desc_struct *gdt_descr = &per_cpu(cpu_gdt_descr, cpu);
#endif

	if (cpu_test_and_set(cpu, cpu_initialized_map))
		return;

	spin_lock(&ctxt_lock);

	memset(&ctxt, 0, sizeof(ctxt));

	ctxt.flags = VGCF_IN_KERNEL;
	ctxt.user_regs.ds = __USER_DS;
	ctxt.user_regs.es = __USER_DS;
	ctxt.user_regs.fs = 0;
	ctxt.user_regs.gs = 0;
	ctxt.user_regs.ss = __KERNEL_DS;
	ctxt.user_regs.eip = (unsigned long)cpu_bringup_and_idle;
	ctxt.user_regs.eflags = X86_EFLAGS_IF | 0x1000; /* IOPL_RING1 */

	memset(&ctxt.fpu_ctxt, 0, sizeof(ctxt.fpu_ctxt));

	smp_trap_init(ctxt.trap_ctxt);

	ctxt.ldt_ents = 0;

	ctxt.gdt_frames[0] = virt_to_mfn(gdt_descr->address);
	ctxt.gdt_ents      = gdt_descr->size / 8;

#ifdef __i386__
	ctxt.user_regs.cs = __KERNEL_CS;
	ctxt.user_regs.esp = idle->thread.esp0 - sizeof(struct pt_regs);

	ctxt.kernel_ss = __KERNEL_DS;
	ctxt.kernel_sp = idle->thread.esp0;

	ctxt.event_callback_cs     = __KERNEL_CS;
	ctxt.event_callback_eip    = (unsigned long)hypervisor_callback;
	ctxt.failsafe_callback_cs  = __KERNEL_CS;
	ctxt.failsafe_callback_eip = (unsigned long)failsafe_callback;

	ctxt.ctrlreg[3] = xen_pfn_to_cr3(virt_to_mfn(swapper_pg_dir));
#else /* __x86_64__ */
	ctxt.user_regs.cs = __KERNEL_CS;
	ctxt.user_regs.esp = idle->thread.rsp0 - sizeof(struct pt_regs);

	ctxt.kernel_ss = __KERNEL_DS;
	ctxt.kernel_sp = idle->thread.rsp0;

	ctxt.event_callback_eip    = (unsigned long)hypervisor_callback;
	ctxt.failsafe_callback_eip = (unsigned long)failsafe_callback;
	ctxt.syscall_callback_eip  = (unsigned long)system_call;

	ctxt.ctrlreg[3] = xen_pfn_to_cr3(virt_to_mfn(init_level4_pgt));

	ctxt.gs_base_kernel = (unsigned long)(cpu_pda(cpu));
#endif

	if (HYPERVISOR_vcpu_op(VCPUOP_initialise, cpu, &ctxt))
		BUG();

	spin_unlock(&ctxt_lock);
}

void __init smp_prepare_cpus(unsigned int max_cpus)
{
	unsigned int cpu;
	struct task_struct *idle;
	int apicid, acpiid;
	struct vcpu_get_physid cpu_id;
#ifdef __x86_64__
	struct desc_ptr *gdt_descr;
#else
	struct Xgt_desc_struct *gdt_descr;
#endif

	apicid = 0;
	if (HYPERVISOR_vcpu_op(VCPUOP_get_physid, 0, &cpu_id) == 0) {
		apicid = xen_vcpu_physid_to_x86_apicid(cpu_id.phys_id);
		acpiid = xen_vcpu_physid_to_x86_acpiid(cpu_id.phys_id);
#ifdef CONFIG_ACPI
		if (acpiid != 0xff)
			x86_acpiid_to_apicid[acpiid] = apicid;
#endif
	}
	boot_cpu_data.apicid = apicid;
	cpu_data[0] = boot_cpu_data;

	x86_cpu_to_apicid[0] = apicid;

	current_thread_info()->cpu = 0;

	for (cpu = 0; cpu < NR_CPUS; cpu++) {
		cpus_clear(cpu_sibling_map[cpu]);
		cpus_clear(cpu_core_map[cpu]);
	}

	set_cpu_sibling_map(0);

	if (xen_smp_intr_init(0))
		BUG();

	cpu_initialized_map = cpumask_of_cpu(0);

	/* Restrict the possible_map according to max_cpus. */
	while ((num_possible_cpus() > 1) && (num_possible_cpus() > max_cpus)) {
		for (cpu = NR_CPUS-1; !cpu_isset(cpu, cpu_possible_map); cpu--)
			continue;
		cpu_clear(cpu, cpu_possible_map);
	}

	for_each_possible_cpu (cpu) {
		if (cpu == 0)
			continue;

#ifdef __x86_64__
		gdt_descr = &cpu_gdt_descr[cpu];
#else
		gdt_descr = &per_cpu(cpu_gdt_descr, cpu);
#endif
		gdt_descr->address = get_zeroed_page(GFP_KERNEL);
		if (unlikely(!gdt_descr->address)) {
			printk(KERN_CRIT "CPU%d failed to allocate GDT\n",
			       cpu);
			continue;
		}
		gdt_descr->size = GDT_SIZE;
		memcpy((void *)gdt_descr->address, cpu_gdt_table, GDT_SIZE);
		make_page_readonly(
			(void *)gdt_descr->address,
			XENFEAT_writable_descriptor_tables);

		apicid = cpu;
		if (HYPERVISOR_vcpu_op(VCPUOP_get_physid, cpu, &cpu_id) == 0) {
			apicid = xen_vcpu_physid_to_x86_apicid(cpu_id.phys_id);
			acpiid = xen_vcpu_physid_to_x86_acpiid(cpu_id.phys_id);
#ifdef CONFIG_ACPI
			if (acpiid != 0xff)
				x86_acpiid_to_apicid[acpiid] = apicid;
#endif
		}
		cpu_data[cpu] = boot_cpu_data;
		cpu_data[cpu].apicid = apicid;

		x86_cpu_to_apicid[cpu] = apicid;

		idle = fork_idle(cpu);
		if (IS_ERR(idle))
			panic("failed fork for CPU %d", cpu);

#ifdef __x86_64__
		cpu_pda(cpu)->pcurrent = idle;
		cpu_pda(cpu)->cpunumber = cpu;
		clear_tsk_thread_flag(idle, TIF_FORK);
#endif

		irq_ctx_init(cpu);

#ifdef CONFIG_HOTPLUG_CPU
		if (is_initial_xendomain())
			cpu_set(cpu, cpu_present_map);
#else
		cpu_set(cpu, cpu_present_map);
#endif
	}

	init_xenbus_allowed_cpumask();

#ifdef CONFIG_X86_IO_APIC
	/*
	 * Here we can be sure that there is an IO-APIC in the system. Let's
	 * go and set it up:
	 */
	if (!skip_ioapic_setup && nr_ioapics)
		setup_IO_APIC();
#endif
}

void __devinit smp_prepare_boot_cpu(void)
{
	prefill_possible_map();
}

#ifdef CONFIG_HOTPLUG_CPU

/*
 * Initialize cpu_present_map late to skip SMP boot code in init/main.c.
 * But do it early enough to catch critical for_each_present_cpu() loops
 * in i386-specific code.
 */
static int __init initialize_cpu_present_map(void)
{
	cpu_present_map = cpu_possible_map;
	return 0;
}
core_initcall(initialize_cpu_present_map);

int __cpu_disable(void)
{
	cpumask_t map = cpu_online_map;
	unsigned int cpu = smp_processor_id();

	if (cpu == 0)
		return -EBUSY;

	remove_siblinginfo(cpu);

	cpu_clear(cpu, map);
	fixup_irqs(map);
	cpu_clear(cpu, cpu_online_map);

	return 0;
}

void __cpu_die(unsigned int cpu)
{
	while (HYPERVISOR_vcpu_op(VCPUOP_is_up, cpu, NULL)) {
		current->state = TASK_UNINTERRUPTIBLE;
		schedule_timeout(HZ/10);
	}

	xen_smp_intr_exit(cpu);

	if (num_online_cpus() == 1)
		alternatives_smp_switch(0);
}

#endif /* CONFIG_HOTPLUG_CPU */

int __cpuinit __cpu_up(unsigned int cpu)
{
	int rc;

	rc = cpu_up_check(cpu);
	if (rc)
		return rc;

	cpu_initialize_context(cpu);

	if (num_online_cpus() == 1)
		alternatives_smp_switch(1);

	/* This must be done before setting cpu_online_map */
	set_cpu_sibling_map(cpu);
	wmb();

	rc = xen_smp_intr_init(cpu);
	if (rc) {
		remove_siblinginfo(cpu);
		return rc;
	}

	cpu_set(cpu, cpu_online_map);

	rc = HYPERVISOR_vcpu_op(VCPUOP_up, cpu, NULL);
	BUG_ON(rc);

	return 0;
}

void __init smp_cpus_done(unsigned int max_cpus)
{
}

#ifndef CONFIG_X86_LOCAL_APIC
int setup_profiling_timer(unsigned int multiplier)
{
	return -EINVAL;
}
#endif
