obj-y			:= boot.o
boot-y			:= ../../../i386/kernel/acpi/boot.o
obj-$(CONFIG_ACPI_SLEEP)	+= sleep.o wakeup.o

ifneq ($(CONFIG_ACPI_PROCESSOR),)
obj-y			+= processor.o
processor-y		:= ../../../i386/kernel/acpi/processor.o ../../../i386/kernel/acpi/cstate.o
processor-$(CONFIG_XEN)	:= ../../../i386/kernel/acpi/processor.o
ifneq ($(CONFIG_PROCESSOR_EXTERNAL_CONTROL),)
processor-$(CONFIG_XEN)	+= ../../../i386/kernel/acpi/processor_extcntl_xen.o
endif
endif

disabled-obj-$(CONFIG_XEN) := wakeup.o
