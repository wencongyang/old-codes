#! /bin/sh

vif=$(ifconfig | awk "\$1 ~ /vif*/ {print \$1}")

function uninstall() {
	tc filter del dev $vif parent 1: protocol ip prio 10 u32
	tc filter del dev $vif parent 1: protocol arp prio 11 u32
	tc qdisc del dev $vif root handle 1: prio

	tc filter del dev $vif parent ffff: protocol ip prio 10 u32
	tc qdisc del dev $vif ingress

	#tc qdisc del dev ifb0 root handle 1: master
	
	tc filter del dev eth0 parent ffff: protocol ip prio 10 u32
	tc qdisc del dev eth0 ingress

	#tc qdisc del dev ifb1 root handle 1: slaver
}

function install() {
	tc qdisc add dev peth1 ingress
	tc filter add dev peth1 parent ffff: protocol ip prio 10 u32 match u32 0 0 flowid 1:2 action mirred egress redirect dev eth0
	tc filter add dev peth1 parent ffff: protocol arp prio 11 u32 match u32 0 0 flowid 1:2 action mirred egress redirect dev eth0

	
	tc qdisc add dev eth0 ingress
	tc filter add dev eth0 parent ffff: protocol ip prio 10 u32 match u32 0 0 flowid 1:2 action mirred egress redirect dev peth1
	tc filter add dev eth0 parent ffff: protocol arp prio 11 u32 match u32 0 0 flowid 1:2 action mirred egress redirect dev peth1
}

uninstall
install
