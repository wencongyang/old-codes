obj-m := sch_master.o sch_slaver.o HA_compare.o
sch_master-objs := master.o hash.o
sch_slaver-objs := slaver.o hash.o
HA_compare-objs := compare.o hash.o
KERNELBUILD := /lib/modules/`uname -r`/build
default:
	make -C $(KERNELBUILD) M=$(shell pwd) modules
clean:
	rm -rf *.o .*.cmd *.ko *.mod.c *.order *.symvers .tmp_versions

