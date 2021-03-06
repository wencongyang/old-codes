#
# Makefile for the ia32 kernel emulation subsystem.
#

obj-$(CONFIG_IA32_EMULATION) := ia32entry.o sys_ia32.o ia32_signal.o tls32.o \
	ia32_binfmt.o fpu32.o ptrace32.o syscall32.o syscall32_syscall.o \
	mmap32.o

sysv-$(CONFIG_SYSVIPC) := ipc32.o
obj-$(CONFIG_IA32_EMULATION) += $(sysv-y)

obj-$(CONFIG_IA32_AOUT) += ia32_aout.o

audit-class-$(CONFIG_AUDIT) := audit.o
obj-$(CONFIG_IA32_EMULATION) += $(audit-class-y)

syscall32-types-y := sysenter syscall
syscall32-types-$(subst 1,$(CONFIG_XEN),$(shell expr $(CONFIG_XEN_COMPAT)0 '<' 0x0302000)) += int80

$(obj)/syscall32_syscall.o: \
	$(foreach F,$(syscall32-types-y),$(obj)/vsyscall-$F.so)

# Teach kbuild about targets
targets := $(foreach F,$(syscall32-types-y),vsyscall-$F.o vsyscall-$F.so)

# The DSO images are built using a special linker script
quiet_cmd_syscall = SYSCALL $@
      cmd_syscall = $(CC) -m32 -nostdlib -shared -s \
			  $(call ld-option, -Wl$(comma)--hash-style=sysv) \
			   -Wl,-soname=linux-gate.so.1 -o $@ \
			   -Wl,-T,$(filter-out FORCE,$^)

$(foreach F,$(syscall32-types-y),$(obj)/vsyscall-$F.so): \
$(obj)/vsyscall-%.so: $(src)/vsyscall.lds $(obj)/vsyscall-%.o FORCE
	$(call if_changed,syscall)

AFLAGS_vsyscall-sysenter.o = -m32 -Wa,-32 -Iarch/i386/kernel
AFLAGS_vsyscall-syscall.o = -m32 -Wa,-32 -Iarch/i386/kernel
AFLAGS_vsyscall-int80.o = -m32 -Wa,-32 -Iarch/i386/kernel
