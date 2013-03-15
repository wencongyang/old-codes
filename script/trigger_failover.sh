#! /bin/sh

vif=$(ifconfig | awk "\$1 ~ /vif*/ {print \$1}")

brctl delif eth1 $vif
echo f > /proc/HA_compare

##
sleep 1
xm des PV
