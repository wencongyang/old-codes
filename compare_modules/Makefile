obj-m := sch_colo.o HA_compare.o
obj-m += HA_compare_arp.o HA_compare_ipv4.o
obj-m += HA_compare_icmp.o HA_compare_tcp.o HA_compare_udp.o
obj-m += HA_compare_tcp_bypass.o HA_compare_udp_bypass.o

sch_colo-objs := colo.o connections.o ipv4_fragment.o ip_fragment.o
HA_compare-objs := compare.o compare_device.o compare_debugfs.o

HA_compare_arp-objs := compare_arp.o
HA_compare_ipv4-objs := compare_ipv4.o

HA_compare_icmp-objs := compare_icmp.o
HA_compare_tcp-objs := compare_tcp.o
HA_compare_udp-objs := compare_udp.o
HA_compare_tcp_bypass-objs := compare_tcp_bypass.o
HA_compare_udp_bypass-objs := compare_udp_bypass.o

KERNELBUILD := /lib/modules/`uname -r`/build
default:
	make -C $(KERNELBUILD) M=$(shell pwd) modules
clean:
	rm -rf *.o .*.cmd *.ko *.mod.c *.order *.symvers .tmp_versions *.unsigned

