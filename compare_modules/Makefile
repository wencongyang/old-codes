obj-m := sch_colo.o HA_compare.o HA_compare_icmp.o

sch_colo-objs := colo.o if_connections.o ipv4_fragment.o ip_fragment.o
HA_compare-objs := compare.o compare_device.o compare_ipv4.o compare_arp.o
HA_compare_icmp-objs := compare_icmp.o
HA_compare_tcp-objs := compare_tcp.o
HA_compare_udp-objs := compare_udp.o
KERNELBUILD := /lib/modules/`uname -r`/build
default:
	make -C $(KERNELBUILD) M=$(shell pwd) modules
clean:
	rm -rf *.o .*.cmd *.ko *.mod.c *.order *.symvers .tmp_versions *.unsigned

