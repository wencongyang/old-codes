/*
 * Support routines for Xen hypercalls
 *
 * Copyright (C) 2005 Dan Magenheimer <dan.magenheimer@hp.com>
 */

#include <asm/asmmacro.h>
#include <asm/intrinsics.h>

#ifdef __INTEL_COMPILER
# undef ASM_SUPPORTED
#else
# define ASM_SUPPORTED
#endif

#ifndef ASM_SUPPORTED
GLOBAL_ENTRY(xen_get_psr)
	XEN_HYPER_GET_PSR
	br.ret.sptk.many rp
	;;
END(xen_get_psr)

GLOBAL_ENTRY(xen_get_ivr)
	XEN_HYPER_GET_IVR
	br.ret.sptk.many rp
	;;
END(xen_get_ivr)

GLOBAL_ENTRY(xen_get_tpr)
	XEN_HYPER_GET_TPR
	br.ret.sptk.many rp
	;;
END(xen_get_tpr)

GLOBAL_ENTRY(xen_set_tpr)
	mov r8=r32
	XEN_HYPER_SET_TPR
	br.ret.sptk.many rp
	;;
END(xen_set_tpr)

GLOBAL_ENTRY(xen_eoi)
	mov r8=r32
	XEN_HYPER_EOI
	br.ret.sptk.many rp
	;;
END(xen_eoi)

GLOBAL_ENTRY(xen_thash)
	mov r8=r32
	XEN_HYPER_THASH
	br.ret.sptk.many rp
	;;
END(xen_thash)

GLOBAL_ENTRY(xen_set_itm)
	mov r8=r32
	XEN_HYPER_SET_ITM
	br.ret.sptk.many rp
	;;
END(xen_set_itm)

GLOBAL_ENTRY(xen_ptcga)
	mov r8=r32
	mov r9=r33
	XEN_HYPER_PTC_GA
	br.ret.sptk.many rp
	;;
END(xen_ptcga)

GLOBAL_ENTRY(xen_get_rr)
	mov r8=r32
	XEN_HYPER_GET_RR
	br.ret.sptk.many rp
	;;
END(xen_get_rr)

GLOBAL_ENTRY(xen_set_rr)
	mov r8=r32
	mov r9=r33
	XEN_HYPER_SET_RR
	br.ret.sptk.many rp
	;;
END(xen_set_rr)

GLOBAL_ENTRY(xen_set_kr)
	mov r8=r32
	mov r9=r33
	XEN_HYPER_SET_KR
	br.ret.sptk.many rp
END(xen_set_kr)

GLOBAL_ENTRY(xen_fc)
	mov r8=r32
	XEN_HYPER_FC
	br.ret.sptk.many rp
END(xen_fc)

GLOBAL_ENTRY(xen_get_cpuid)
	mov r8=r32
	XEN_HYPER_GET_CPUID
	br.ret.sptk.many rp
END(xen_get_cpuid)

GLOBAL_ENTRY(xen_get_pmd)
	mov r8=r32
	XEN_HYPER_GET_PMD
	br.ret.sptk.many rp
END(xen_get_pmd)

#ifdef CONFIG_IA32_SUPPORT
GLOBAL_ENTRY(xen_get_eflag)
	XEN_HYPER_GET_EFLAG
	br.ret.sptk.many rp
END(xen_get_eflag)
	
// some bits aren't set if pl!=0, see SDM vol1 3.1.8
GLOBAL_ENTRY(xen_set_eflag)
	mov r8=r32
	XEN_HYPER_SET_EFLAG
	br.ret.sptk.many rp
END(xen_set_eflag)
#endif /* CONFIG_IA32_SUPPORT */
#endif /* ASM_SUPPORTED */

GLOBAL_ENTRY(xen_send_ipi)
	mov r14=r32
	mov r15=r33
	mov r2=0x400
	break 0x1000
	;;
	br.ret.sptk.many rp
	;;
END(xen_send_ipi)

GLOBAL_ENTRY(__hypercall)
	mov r2=r37
	break 0x1000
	br.ret.sptk.many b0
	;; 
END(__hypercall)
