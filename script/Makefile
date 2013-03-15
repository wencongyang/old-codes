
XEN_SCRIPT_PATH=/etc/xen/scripts/

.PHONY: all

all:

install: HA_fw_runtime.sh
	mkdir -p ${XEN_SCRIPT_PATH}
	cp HA_fw_runtime.sh ${XEN_SCRIPT_PATH}
	cp failover_master.sh ${XEN_SCRIPT_PATH}
