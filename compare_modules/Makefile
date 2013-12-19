obj-m := sch_master.o sch_slaver.o HA_compare.o
sch_master-objs := sch_master_1.o hash.o
sch_slaver-objs := sch_slaver_1.o hash.o
HA_compare-objs := HA_compare_1.o hash.o
KERNELBUILD := /lib/modules/`uname -r`/build
default:
	make -C $(KERNELBUILD) M=$(shell pwd) modules
clean:
	rm -rf *.o .*.cmd *.ko *.mod.c *.order *.symvers .tmp_versions

