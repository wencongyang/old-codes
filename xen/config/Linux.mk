include $(XEN_ROOT)/config/StdGNU.mk

# You may use wildcards, e.g. KERNELS=*2.6*
KERNELS ?= linux-2.6-xenU

XKERNELS := $(foreach kernel, $(KERNELS), \
              $(patsubst buildconfigs/mk.%,%, \
                $(wildcard buildconfigs/mk.$(kernel))) )
