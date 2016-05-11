ifneq ($(KERNELRELEASE),)
# kbuild part of makefile
 obj-m  := sch_plug.o

else
# normal makefile
 KDIR ?= /lib/modules/`uname -r`/build

 default:
	$(MAKE) -C $(KDIR) M=$$PWD

 install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install && /sbin/depmod -a

 clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean

endif
