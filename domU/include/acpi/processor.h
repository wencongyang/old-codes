#ifndef __ACPI_PROCESSOR_H
#define __ACPI_PROCESSOR_H

#include <linux/kernel.h>
#include <linux/cpu.h>

#include <asm/acpi.h>

#define ACPI_PROCESSOR_BUSY_METRIC	10

#define ACPI_PROCESSOR_MAX_POWER	8
#define ACPI_PROCESSOR_MAX_C2_LATENCY	100
#define ACPI_PROCESSOR_MAX_C3_LATENCY	1000

#define ACPI_PROCESSOR_MAX_THROTTLING	16
#define ACPI_PROCESSOR_MAX_THROTTLE	250	/* 25% */
#define ACPI_PROCESSOR_MAX_DUTY_WIDTH	4

#define ACPI_PDC_REVISION_ID		0x1

#define ACPI_PSD_REV0_REVISION		0	/* Support for _PSD as in ACPI 3.0 */
#define ACPI_PSD_REV0_ENTRIES		5

#define ACPI_TSD_REV0_REVISION		0	/* Support for _PSD as in ACPI 3.0 */
#define ACPI_TSD_REV0_ENTRIES		5

#ifdef CONFIG_XEN
#define NR_ACPI_CPUS			(NR_CPUS < 256 ? 256 : NR_CPUS)
#else
#define NR_ACPI_CPUS			NR_CPUS
#endif /* CONFIG_XEN */

/*
 * Types of coordination defined in ACPI 3.0. Same macros can be used across
 * P, C and T states
 */
#define DOMAIN_COORD_TYPE_SW_ALL	0xfc
#define DOMAIN_COORD_TYPE_SW_ANY	0xfd
#define DOMAIN_COORD_TYPE_HW_ALL	0xfe

/* Power Management */

struct acpi_processor_cx;

#ifdef CONFIG_PROCESSOR_EXTERNAL_CONTROL
struct acpi_csd_package {
	acpi_integer num_entries;
	acpi_integer revision;
	acpi_integer domain;
	acpi_integer coord_type;
	acpi_integer num_processors;
	acpi_integer index;
} __attribute__ ((packed));
#endif

struct acpi_power_register {
	u8 descriptor;
	u16 length;
	u8 space_id;
	u8 bit_width;
	u8 bit_offset;
	u8 reserved;
	u64 address;
} __attribute__ ((packed));

struct acpi_processor_cx_policy {
	u32 count;
	struct acpi_processor_cx *state;
	struct {
		u32 time;
		u32 ticks;
		u32 count;
		u32 bm;
	} threshold;
};

struct acpi_processor_cx {
	u8 valid;
	u8 type;
	u32 address;
	u32 latency;
	u32 latency_ticks;
	u32 power;
	u32 usage;
	u64 time;
#ifdef CONFIG_PROCESSOR_EXTERNAL_CONTROL
	/* Require raw information for external control logic */
	struct acpi_power_register reg;
	u32 csd_count;
	struct acpi_csd_package *domain_info;
#endif
	struct acpi_processor_cx_policy promotion;
	struct acpi_processor_cx_policy demotion;
};

struct acpi_processor_power {
	struct acpi_processor_cx *state;
	unsigned long bm_check_timestamp;
	u32 default_state;
	u32 bm_activity;
	int count;
	struct acpi_processor_cx states[ACPI_PROCESSOR_MAX_POWER];
};

/* Performance Management */

struct acpi_psd_package {
	acpi_integer num_entries;
	acpi_integer revision;
	acpi_integer domain;
	acpi_integer coord_type;
	acpi_integer num_processors;
} __attribute__ ((packed));

struct acpi_pct_register {
	u8 descriptor;
	u16 length;
	u8 space_id;
	u8 bit_width;
	u8 bit_offset;
	u8 reserved;
	u64 address;
} __attribute__ ((packed));

struct acpi_processor_px {
	acpi_integer core_frequency;	/* megahertz */
	acpi_integer power;	/* milliWatts */
	acpi_integer transition_latency;	/* microseconds */
	acpi_integer bus_master_latency;	/* microseconds */
	acpi_integer control;	/* control value */
	acpi_integer status;	/* success indicator */
};

struct acpi_processor_performance {
	unsigned int state;
	unsigned int platform_limit;
	struct acpi_pct_register control_register;
	struct acpi_pct_register status_register;
	unsigned int state_count;
	struct acpi_processor_px *states;
	struct acpi_psd_package domain_info;
	cpumask_t shared_cpu_map;
	unsigned int shared_type;
};

/* Throttling Control */

struct acpi_tsd_package {
	acpi_integer num_entries;
	acpi_integer revision;
	acpi_integer domain;
	acpi_integer coord_type;
	acpi_integer num_processors;
} __attribute__ ((packed));

struct acpi_ptc_register {
	u8 descriptor;
	u16 length;
	u8 space_id;
	u8 bit_width;
	u8 bit_offset;
	u8 reserved;
	u64 address;
} __attribute__ ((packed));

struct acpi_processor_tx_tss {
	acpi_integer freqpercentage;	/* */
	acpi_integer power;	/* milliWatts */
	acpi_integer transition_latency;	/* microseconds */
	acpi_integer control;	/* control value */
	acpi_integer status;	/* success indicator */
};
struct acpi_processor_tx {
	u16 power;
	u16 performance;
};

struct acpi_processor;
struct acpi_processor_throttling {
	unsigned int state;
	unsigned int platform_limit;
	struct acpi_pct_register control_register;
	struct acpi_pct_register status_register;
	unsigned int state_count;
	struct acpi_processor_tx_tss *states_tss;
	struct acpi_tsd_package domain_info;
	cpumask_t shared_cpu_map;
	int (*acpi_processor_get_throttling) (struct acpi_processor * pr);
	int (*acpi_processor_set_throttling) (struct acpi_processor * pr,
					      int state);

	u32 address;
	u8 duty_offset;
	u8 duty_width;
	u8 tsd_valid_flag;
	unsigned int shared_type;
	struct acpi_processor_tx states[ACPI_PROCESSOR_MAX_THROTTLING];
};

/* Limit Interface */

struct acpi_processor_lx {
	int px;			/* performance state */
	int tx;			/* throttle level */
};

struct acpi_processor_limit {
	struct acpi_processor_lx state;	/* current limit */
	struct acpi_processor_lx thermal;	/* thermal limit */
	struct acpi_processor_lx user;	/* user limit */
};

struct acpi_processor_flags {
	u8 power:1;
	u8 performance:1;
	u8 throttling:1;
	u8 limit:1;
	u8 bm_control:1;
	u8 bm_check:1;
	u8 has_cst:1;
	u8 power_setup_done:1;
};

struct acpi_processor {
	acpi_handle handle;
	u32 acpi_id;
	u32 id;
	u32 pblk;
	int performance_platform_limit;
	int throttling_platform_limit;
	/* 0 - states 0..n-th state available */

	struct acpi_processor_flags flags;
	struct acpi_processor_power power;
	struct acpi_processor_performance *performance;
	struct acpi_processor_throttling throttling;
	struct acpi_processor_limit limit;

	/* the _PDC objects for this processor, if any */
	struct acpi_object_list *pdc;
};

struct acpi_processor_errata {
	u8 smp;
	struct {
		u8 throttle:1;
		u8 fdma:1;
		u8 reserved:6;
		u32 bmisx;
	} piix4;
};

extern int acpi_processor_preregister_performance(
		struct acpi_processor_performance **performance);

extern int acpi_processor_register_performance(struct acpi_processor_performance
					       *performance, unsigned int cpu);
extern void acpi_processor_unregister_performance(struct
						  acpi_processor_performance
						  *performance,
						  unsigned int cpu);

/* note: this locks both the calling module and the processor module
         if a _PPC object exists, rmmod is disallowed then */
int acpi_processor_notify_smm(struct module *calling_module);

/* for communication between multiple parts of the processor kernel module */
extern struct acpi_processor *processors[NR_CPUS];
extern struct acpi_processor_errata errata;

void arch_acpi_processor_init_pdc(struct acpi_processor *pr);

#ifdef ARCH_HAS_POWER_INIT
void acpi_processor_power_init_bm_check(struct acpi_processor_flags *flags,
					unsigned int cpu);
#else
static inline void acpi_processor_power_init_bm_check(struct
						      acpi_processor_flags
						      *flags, unsigned int cpu)
{
	flags->bm_check = 1;
	return;
}
#endif

/* in processor_perflib.c */

#ifdef CONFIG_CPU_FREQ
void acpi_processor_ppc_init(void);
void acpi_processor_ppc_exit(void);
int acpi_processor_ppc_has_changed(struct acpi_processor *pr);
#else
static inline void acpi_processor_ppc_init(void)
{
	return;
}
static inline void acpi_processor_ppc_exit(void)
{
	return;
}
#ifdef CONFIG_PROCESSOR_EXTERNAL_CONTROL
int acpi_processor_ppc_has_changed(struct acpi_processor *pr);
#else
static inline int acpi_processor_ppc_has_changed(struct acpi_processor *pr)
{
	static unsigned int printout = 1;
	if (printout) {
		printk(KERN_WARNING
		       "Warning: Processor Platform Limit event detected, but not handled.\n");
		printk(KERN_WARNING
		       "Consider compiling CPUfreq support into your kernel.\n");
		printout = 0;
	}
	return 0;
}
#endif				/* CONFIG_PROCESSOR_EXTERNAL_CONTROL */
#endif				/* CONFIG_CPU_FREQ */

/* in processor_throttling.c */
int acpi_processor_tstate_has_changed(struct acpi_processor *pr);
int acpi_processor_get_throttling_info(struct acpi_processor *pr);
extern int acpi_processor_set_throttling(struct acpi_processor *pr, int state);
extern struct file_operations acpi_processor_throttling_fops;
extern void acpi_processor_throttling_init(void);
/* in processor_idle.c */
int acpi_processor_power_init(struct acpi_processor *pr,
			      struct acpi_device *device);
int acpi_processor_cst_has_changed(struct acpi_processor *pr);
int acpi_processor_power_exit(struct acpi_processor *pr,
			      struct acpi_device *device);

/* in processor_thermal.c */
int acpi_processor_get_limit_info(struct acpi_processor *pr);
extern struct file_operations acpi_processor_limit_fops;

#ifdef CONFIG_CPU_FREQ
void acpi_thermal_cpufreq_init(void);
void acpi_thermal_cpufreq_exit(void);
#else
static inline void acpi_thermal_cpufreq_init(void)
{
	return;
}
static inline void acpi_thermal_cpufreq_exit(void)
{
	return;
}
#endif

/* 
 * Following are interfaces geared to external processor PM control
 * logic like a VMM
 */
/* Events notified to external control logic */
#define PROCESSOR_PM_INIT	1
#define PROCESSOR_PM_CHANGE	2
#define PROCESSOR_HOTPLUG	3

/* Objects for the PM events */
#define PM_TYPE_IDLE		0
#define PM_TYPE_PERF		1
#define PM_TYPE_THR		2
#define PM_TYPE_MAX		3

/* Processor hotplug events */
#define HOTPLUG_TYPE_ADD	0
#define HOTPLUG_TYPE_REMOVE	1

#ifdef CONFIG_PROCESSOR_EXTERNAL_CONTROL
struct processor_extcntl_ops {
	/* Transfer processor PM events to external control logic */
	int (*pm_ops[PM_TYPE_MAX])(struct acpi_processor *pr, int event);
	/* Notify physical processor status to external control logic */
	int (*hotplug)(struct acpi_processor *pr, int type);
};
extern const struct processor_extcntl_ops *processor_extcntl_ops;

static inline int processor_cntl_external(void)
{
	return (processor_extcntl_ops != NULL);
}

static inline int processor_pm_external(void)
{
	return processor_cntl_external() &&
		(processor_extcntl_ops->pm_ops[PM_TYPE_IDLE] != NULL);
}

static inline int processor_pmperf_external(void)
{
	return processor_cntl_external() &&
		(processor_extcntl_ops->pm_ops[PM_TYPE_PERF] != NULL);
}

static inline int processor_pmthr_external(void)
{
	return processor_cntl_external() &&
		(processor_extcntl_ops->pm_ops[PM_TYPE_THR] != NULL);
}

extern int processor_notify_external(struct acpi_processor *pr,
			int event, int type);
extern void processor_extcntl_init(void);
extern int processor_extcntl_prepare(struct acpi_processor *pr);
extern int acpi_processor_get_performance_info(struct acpi_processor *pr);
extern int acpi_processor_get_psd(struct acpi_processor *pr);
void arch_acpi_processor_init_extcntl(const struct processor_extcntl_ops **);
#else
static inline int processor_cntl_external(void) {return 0;}
static inline int processor_pm_external(void) {return 0;}
static inline int processor_pmperf_external(void) {return 0;}
static inline int processor_pmthr_external(void) {return 0;}
static inline int processor_notify_external(struct acpi_processor *pr,
			int event, int type)
{
	return 0;
}
static inline void processor_extcntl_init(void) {}
static inline int processor_extcntl_prepare(struct acpi_processor *pr)
{
	return 0;
}
#endif /* CONFIG_PROCESSOR_EXTERNAL_CONTROL */

#ifdef CONFIG_XEN
static inline void xen_convert_pct_reg(struct xen_pct_register *xpct,
	struct acpi_pct_register *apct)
{
	xpct->descriptor = apct->descriptor;
	xpct->length     = apct->length;
	xpct->space_id   = apct->space_id;
	xpct->bit_width  = apct->bit_width;
	xpct->bit_offset = apct->bit_offset;
	xpct->reserved   = apct->reserved;
	xpct->address    = apct->address;
}

static inline void xen_convert_pss_states(struct xen_processor_px *xpss, 
	struct acpi_processor_px *apss, int state_count)
{
	int i;
	for(i=0; i<state_count; i++) {
		xpss->core_frequency     = apss->core_frequency;
		xpss->power              = apss->power;
		xpss->transition_latency = apss->transition_latency;
		xpss->bus_master_latency = apss->bus_master_latency;
		xpss->control            = apss->control;
		xpss->status             = apss->status;
		xpss++;
		apss++;
	}
}

static inline void xen_convert_psd_pack(struct xen_psd_package *xpsd,
	struct acpi_psd_package *apsd)
{
	xpsd->num_entries    = apsd->num_entries;
	xpsd->revision       = apsd->revision;
	xpsd->domain         = apsd->domain;
	xpsd->coord_type     = apsd->coord_type;
	xpsd->num_processors = apsd->num_processors;
}

#endif /* CONFIG_XEN */

#endif
