obj-bin-y += head.o

head.o: reloc.S

BOOT_TRAMPOLINE := $(shell sed -n 's,^\#define[[:space:]]\{1\,\}BOOT_TRAMPOLINE[[:space:]]\{1\,\},,p' $(BASEDIR)/include/asm-x86/config.h)
%.S: %.c
	RELOC=$(BOOT_TRAMPOLINE) $(MAKE) -f build32.mk $@

reloc.S: $(BASEDIR)/include/asm-x86/config.h
