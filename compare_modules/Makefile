obj-m := sch_colo.o HA_compare.o

sch_colo-objs := colo.o hash.o
HA_compare-objs := compare.o hash.o
KERNELBUILD := /lib/modules/`uname -r`/build
default:
	make -C $(KERNELBUILD) M=$(shell pwd) modules
clean:
	rm -rf *.o .*.cmd *.ko *.mod.c *.order *.symvers .tmp_versions

