
override XEN_TARGET_ARCH = x86_32
XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk
include Config

ifeq ($(GIT_HTTP),y)
IPXE_GIT_URL := http://git.ipxe.org/ipxe.git
else
IPXE_GIT_URL := git://git.ipxe.org/ipxe.git
endif

IPXE_GIT_TAG := v1.0.0

IPXE_TARBALL_URL := $(XEN_EXTFILES_URL)/ipxe-git-$(IPXE_GIT_TAG).tar.gz

D=ipxe
T=ipxe.tar.gz

ROMS = $(addprefix $D/src/bin/, $(addsuffix .rom, $(NICS)))

.NOTPARALLEL:

.PHONY: all
all: eb-roms.h

%.rom: $D/src/arch/i386/Makefile
	$(MAKE) -C $D/src bin/$(*F).rom

eb-roms.h.new: $(ROMS)
	cat $^ | ../hvmloader/mkhex etherboot >$@

eb-roms.h: Config
	$(MAKE) NO_WERROR=1 $@.new
	mv -f $@.new $@

$T:
	if ! wget -O _$T $(IPXE_TARBALL_URL); then \
		$(GIT) clone $(IPXE_GIT_URL) $D.git; \
		(cd $D.git && $(GIT) archive --format=tar --prefix=$D/ \
		$(IPXE_GIT_TAG) | gzip >../_$T); \
		rm -rf $D.git; \
	fi
	mv _$T $T

$D/src/arch/i386/Makefile: $T Config
	rm -rf $D
	gzip -dc $T | tar xf -
	for i in $$(cat patches/series) ; do                 \
	    patch -d $D -p1 --quiet <patches/$$i || exit 1 ; \
	done
	cat Config >>$@

$D/src/bin/NIC: $D/src/arch/i386/Makefile
	$(MAKE) -C $D/src bin/NIC

.PHONY: clean
clean:
	rm -rf $D $D.git *~ eb-roms.h _$T

.PHONY: distclean
distclean: clean
	rm -rf $T
