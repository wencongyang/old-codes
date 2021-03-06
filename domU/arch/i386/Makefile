#
# i386/Makefile
#
# This file is included by the global makefile so that you can add your own
# architecture-specific flags and dependencies. Remember to do have actions
# for "archclean" cleaning up for this architecture.
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
# Copyright (C) 1994 by Linus Torvalds
#
# 19990713  Artur Skawina <skawina@geocities.com>
#           Added '-march' and '-mpreferred-stack-boundary' support
#
# 20050320  Kianusch Sayah Karadji <kianusch@sk-tech.net>
#           Added support for GEODE CPU

HAS_BIARCH      := $(call cc-option-yn, -m32)
ifeq ($(HAS_BIARCH),y)
AS              := $(AS) --32
LD              := $(LD) -m elf_i386
CC              := $(CC) -m32
endif

LDFLAGS		:= -m elf_i386
OBJCOPYFLAGS	:= -O binary -R .note -R .comment -S
LDFLAGS_vmlinux :=
CHECKFLAGS	+= -D__i386__

CFLAGS += -pipe -msoft-float

# prevent gcc from keeping the stack 16 byte aligned
CFLAGS += $(call cc-option,-mpreferred-stack-boundary=2)

# CPU-specific tuning. Anything which can be shared with UML should go here.
include $(srctree)/arch/i386/Makefile.cpu

cflags-$(CONFIG_REGPARM) += -mregparm=3

# temporary until string.h is fixed
cflags-y += -ffreestanding

# Disable unit-at-a-time mode on pre-gcc-4.0 compilers, it makes gcc use
# a lot more stack due to the lack of sharing of stacklots:
CFLAGS				+= $(shell if [ $(call cc-version) -lt 0400 ] ; then echo $(call cc-option,-fno-unit-at-a-time); fi ;)

CFLAGS += $(cflags-y)

# Default subarch .c files
mcore-y  := mach-default

# Voyager subarch support
mflags-$(CONFIG_X86_VOYAGER)	:= -Iinclude/asm-i386/mach-voyager
mcore-$(CONFIG_X86_VOYAGER)	:= mach-voyager

# VISWS subarch support
mflags-$(CONFIG_X86_VISWS)	:= -Iinclude/asm-i386/mach-visws
mcore-$(CONFIG_X86_VISWS)	:= mach-visws

# NUMAQ subarch support
mflags-$(CONFIG_X86_NUMAQ)	:= -Iinclude/asm-i386/mach-numaq
mcore-$(CONFIG_X86_NUMAQ)	:= mach-default

# BIGSMP subarch support
mflags-$(CONFIG_X86_BIGSMP)	:= -Iinclude/asm-i386/mach-bigsmp
mcore-$(CONFIG_X86_BIGSMP)	:= mach-default

#Summit subarch support
mflags-$(CONFIG_X86_SUMMIT) := -Iinclude/asm-i386/mach-summit
mcore-$(CONFIG_X86_SUMMIT)  := mach-default

# Xen subarch support
mflags-$(CONFIG_X86_XEN)	:= -Iinclude/asm-i386/mach-xen
mcore-$(CONFIG_X86_XEN)		:= mach-xen

# generic subarchitecture
mflags-$(CONFIG_X86_GENERICARCH) := -Iinclude/asm-i386/mach-generic
mcore-$(CONFIG_X86_GENERICARCH) := mach-default
core-$(CONFIG_X86_GENERICARCH) += arch/i386/mach-generic/

# ES7000 subarch support
mflags-$(CONFIG_X86_ES7000)	:= -Iinclude/asm-i386/mach-es7000
mcore-$(CONFIG_X86_ES7000)	:= mach-default
core-$(CONFIG_X86_ES7000)	:= arch/i386/mach-es7000/

# default subarch .h files
mflags-y += -Iinclude/asm-i386/mach-default

head-y := arch/i386/kernel/head.o arch/i386/kernel/init_task.o

libs-y 					+= arch/i386/lib/
core-y					+= arch/i386/kernel/ \
					   arch/i386/mm/ \
					   arch/i386/$(mcore-y)/ \
					   arch/i386/crypto/
drivers-$(CONFIG_MATH_EMULATION)	+= arch/i386/math-emu/
drivers-$(CONFIG_PCI)			+= arch/i386/pci/
# must be linked after kernel/
drivers-$(CONFIG_OPROFILE)		+= arch/i386/oprofile/
drivers-$(CONFIG_PM)			+= arch/i386/power/

CFLAGS += $(mflags-y)
AFLAGS += $(mflags-y)

boot := arch/i386/boot

PHONY += zImage bzImage vmlinuz compressed zlilo bzlilo \
         zdisk bzdisk fdimage fdimage144 fdimage288 isoimage install

ifdef CONFIG_XEN
CPPFLAGS := -D__XEN_INTERFACE_VERSION__=$(CONFIG_XEN_INTERFACE_VERSION) \
	-Iinclude$(if $(KBUILD_SRC),2)/asm/mach-xen $(CPPFLAGS)
all: vmlinuz

# KBUILD_IMAGE specifies the target image being built
KBUILD_IMAGE := $(boot)/vmlinuz

vmlinuz: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) $(KBUILD_IMAGE)
else
all: bzImage

# KBUILD_IMAGE specify target image being built
                    KBUILD_IMAGE := $(boot)/bzImage
zImage zlilo zdisk: KBUILD_IMAGE := arch/i386/boot/zImage

zImage bzImage: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) $(KBUILD_IMAGE)

compressed: zImage

zlilo bzlilo: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) BOOTIMAGE=$(KBUILD_IMAGE) zlilo

zdisk bzdisk: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) BOOTIMAGE=$(KBUILD_IMAGE) zdisk

fdimage fdimage144 fdimage288 isoimage: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) BOOTIMAGE=$(KBUILD_IMAGE) $@
endif

install:
	$(Q)$(MAKE) $(build)=$(boot) BOOTIMAGE=$(KBUILD_IMAGE) install

archclean:
	$(Q)$(MAKE) $(clean)=arch/i386/boot

define archhelp
  echo  '* bzImage	- Compressed kernel image (arch/$(ARCH)/boot/bzImage)'
  echo  '  install	- Install kernel using'
  echo  '		   (your) ~/bin/installkernel or'
  echo  '		   (distribution) /sbin/installkernel or'
  echo  '		   install to $$(INSTALL_PATH) and run lilo'
  echo  '  bzdisk       - Create a boot floppy in /dev/fd0'
  echo  '  fdimage      - Create a boot floppy image'
  echo  '  isoimage     - Create a boot CD-ROM image'
endef

CLEAN_FILES += arch/$(ARCH)/boot/fdimage \
	       arch/$(ARCH)/boot/image.iso \
	       arch/$(ARCH)/boot/mtools.conf
