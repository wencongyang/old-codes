#! /bin/sh
# This script configurates the network of Master & Slaver.
# Ye Wei- 2011/12/21
#
module="HA_compare"
device="HA_compare"
mode="664"

function getvif() {
	local vif=$(ifconfig | awk "\$1 ~ /vif*/ {print \$1}")
	echo $vif
}

function start() {
	echo "start"

	ip link set dev $1 qlen 40960

	tc qdisc add dev $1 root handle 1: prio
	tc filter add dev $1 parent 1: protocol ip prio 10 u32 match u32 0 0 flowid 1:2 action mirred egress mirror dev eth0
	tc filter add dev $1 parent 1: protocol arp prio 11 u32 match u32 0 0 flowid 1:2 action mirred egress mirror dev eth0

	tc qdisc add dev $1 ingress
	tc filter add dev $1 parent ffff: protocol ip prio 10 u32 match u32 0 0 flowid 1:2 action mirred egress redirect dev ifb0
	tc filter add dev $1 parent ffff: protocol arp prio 11 u32 match u32 0 0 flowid 1:2 action mirred egress redirect dev ifb0
}

function stop() {
	echo "stop"

	brctl delif eth1 $1

	tc filter del dev $1 parent 1: protocol ip prio 10 u32
	tc filter del dev $1 parent 1: protocol arp prio 11 u32
	tc qdisc del dev $1 root handle 1: prio

	tc filter del dev $1 parent ffff: protocol ip prio 10 u32
	tc filter del dev $1 parent ffff: protocol arp prio 11 u32
	tc qdisc del dev $1 ingress
}

function install()
{
	echo "install"
	modprobe sch_master || exit 1
	modprobe sch_slaver || exit 1
	modprobe $module || exit 1
	rm -f /dev/${device}
	major=$(awk "\$2==\"$module\" {print \$1}" /proc/devices)
	mknod /dev/$device c $major 0

	ifconfig eth0 promisc
	ip link set dev eth0 qlen 40960

	modprobe ifb
	ip link set ifb0 up
	ip link set ifb0 qlen 40960
	tc qdisc add dev ifb0 root handle 1: master

	ip link set ifb1 up
	ip link set ifb1 qlen 40960
	tc qdisc add dev ifb1 root handle 1: slaver
	tc qdisc add dev eth0 ingress
	tc filter add dev eth0 parent ffff: protocol ip prio 10 u32 match u32 0 0 flowid 1:2 action mirred egress redirect dev ifb1
	tc filter add dev eth0 parent ffff: protocol arp prio 11 u32 match u32 0 0 flowid 1:2 action mirred egress redirect dev ifb1

	start $1

	echo "done"
	exit 1
} #install()

function uninstall()
{
	echo "uninstall";

	stop $1

	tc qdisc del dev ifb0 root handle 1: master
	ip link set ifb0 down

	tc filter del dev eth0 parent ffff: protocol ip prio 10 u32
	tc qdisc del dev eth0 ingress

	tc qdisc del dev ifb1 root handle 1: slaver
	ip link set ifb1 down

	rmmod ifb
	rmmod HA_compare
	rmmod sch_slaver # sch_slaver has a dependence on sch_master
	rmmod sch_master

	ifconfig eth0 -promisc

	echo "done"
	exit 1
} #uninstall()

if [ $# -ne 2 ]; then
	echo "Usage: $0 (install|uninstall) vnif"
	exit 1
fi

vnif=$(getvif)
if [ ! $vnif ]; then
	echo "No Vm"
	exit 1
fi

if [ $1 == "install" ]; then
	install $vnif
elif [ $1 == "uninstall" ]; then
	uninstall $vnif
else
	echo "Usage: $0 (install|uninstall)"
	exit 1
fi
