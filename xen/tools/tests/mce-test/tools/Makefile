XEN_ROOT=../../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS   += -Werror

INCLUDES += -I $(XEN_XC)
INCLUDES += -I $(XEN_LIBXC)
INCLUDES += -I $(XEN_INCLUDE)
CFLAGS   += $(INCLUDES)

HDRS     = $(wildcard *.h)

.PHONY: all
all: xen-mceinj

install: 
	cp xen-mceinj /usr/sbin/

.PHONY: clean
clean:
	$(RM) *.o xen-mceinj

%.o: %.c $(HDRS) Makefile
	$(CC) -c $(CFLAGS) -o $@ $<

xen-mceinj: %: %.o Makefile
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxenstore)
