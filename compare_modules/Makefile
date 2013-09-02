obj-m := sch_colo.o HA_compare.o

sch_colo-objs := colo.o hash.o ip4_fragment.o
HA_compare-objs := compare.o compare_tcp.o compare_udp.o compare_ip.o
KERNELBUILD := /lib/modules/`uname -r`/build
default:
	make -C $(KERNELBUILD) M=$(shell pwd) modules
clean:
	rm -rf *.o .*.cmd *.ko *.mod.c *.order *.symvers .tmp_versions

