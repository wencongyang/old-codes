#
# tools/libxl/Makefile
#

XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR = 1.0
MINOR = 0

XLUMAJOR = 1.0
XLUMINOR = 0

CFLAGS += -Werror -Wno-format-zero-length -Wmissing-declarations
CFLAGS += -I. -fPIC
CFLAGS += $(CFLAGS_libxenctrl) $(CFLAGS_libxenguest) $(CFLAGS_libxenstore) $(CFLAGS_libblktapctl)

LIBS = $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxenstore) $(LDLIBS_libblktapctl) $(UTIL_LIBS)
ifeq ($(CONFIG_Linux),y)
LIBS += -luuid
endif

LIBXL_OBJS-y = osdeps.o libxl_paths.o libxl_bootloader.o flexarray.o
ifeq ($(LIBXL_BLKTAP),y)
LIBXL_OBJS-y += libxl_blktap2.o
else
LIBXL_OBJS-y += libxl_noblktap2.o
endif
LIBXL_OBJS-$(CONFIG_X86) += libxl_cpuid.o
LIBXL_OBJS-$(CONFIG_IA64) += libxl_nocpuid.o

LIBXL_OBJS = flexarray.o libxl.o libxl_create.o libxl_dm.o libxl_pci.o \
			libxl_dom.o libxl_exec.o libxl_xshelp.o libxl_device.o \
			libxl_internal.o libxl_utils.o $(LIBXL_OBJS-y)
LIBXL_OBJS += _libxl_types.o

AUTOINCS= libxlu_cfg_y.h libxlu_cfg_l.h
AUTOSRCS= libxlu_cfg_y.c libxlu_cfg_l.c
LIBXLU_OBJS = libxlu_cfg_y.o libxlu_cfg_l.o libxlu_cfg.o

CLIENTS = xl

XL_OBJS = xl.o xl_cmdimpl.o xl_cmdtable.o

.PHONY: all
all: $(CLIENTS) libxenlight.so libxenlight.a libxlutil.so libxlutil.a \
	$(AUTOSRCS) $(AUTOINCS)

$(LIBXLU_OBJS): $(AUTOINCS)

%.c %.h: %.y
	@rm -f $*.[ch]
	$(BISON) --output=$*.c $<

%.c %.h: %.l
	@rm -f $*.[ch]
	$(FLEX) --header-file=$*.h --outfile=$*.c $<

genpath-target = $(call buildmakevars2file,_libxl_paths.h.tmp)
$(eval $(genpath-target))

_libxl_paths.h: genpath
	sed -e "s/\([^=]*\)=\(.*\)/#define \1 \2/g" $@.tmp >$@.2.tmp
	if ! cmp $@.2.tmp $@; then mv -f $@.2.tmp $@; fi

libxl_paths.c: _libxl_paths.h

libxl.h: _libxl_types.h

$(LIBXL_OBJS) $(LIBXLU_OBJS) $(XL_OBJS): libxl.h

_libxl_%.h _libxl_%.c: libxl.idl gen%.py libxl%.py
	$(PYTHON) gen$*.py libxl.idl __libxl_$*.h __libxl_$*.c
	mv __libxl_$*.h _libxl_$*.h
	mv __libxl_$*.c _libxl_$*.c

libxenlight.so: libxenlight.so.$(MAJOR)
	ln -sf $< $@

libxenlight.so.$(MAJOR): libxenlight.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

libxenlight.so.$(MAJOR).$(MINOR): $(LIBXL_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenlight.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $^

libxenlight.a: $(LIBXL_OBJS)
	$(AR) rcs libxenlight.a $^

libxlutil.so: libxlutil.so.$(XLUMAJOR)
	ln -sf $< $@

libxlutil.so.$(XLUMAJOR): libxlutil.so.$(XLUMAJOR).$(XLUMINOR)
	ln -sf $< $@

libxlutil.so.$(XLUMAJOR).$(XLUMINOR): $(LIBXLU_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxlutil.so.$(XLUMAJOR) $(SHLIB_LDFLAGS) -o $@ $^

libxlutil.a: $(LIBXLU_OBJS)
	$(AR) rcs libxlutil.a $^

$(CLIENTS): $(XL_OBJS) libxlutil.so libxenlight.so
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL_DIR) $(DESTDIR)$(LIBDIR)
	$(INSTALL_DIR) $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_DIR) $(DESTDIR)$(BASH_COMPLETION_DIR)
	$(INSTALL_PROG) xl $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) libxenlight.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)
	ln -sf libxenlight.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)/libxenlight.so.$(MAJOR)
	ln -sf libxenlight.so.$(MAJOR) $(DESTDIR)$(LIBDIR)/libxenlight.so
	$(INSTALL_DATA) libxenlight.a $(DESTDIR)$(LIBDIR)
	$(INSTALL_PROG) libxlutil.so.$(XLUMAJOR).$(XLUMINOR) $(DESTDIR)$(LIBDIR)
	ln -sf libxlutil.so.$(XLUMAJOR).$(XLUMINOR) $(DESTDIR)$(LIBDIR)/libxlutil.so.$(XLUMAJOR)
	ln -sf libxlutil.so.$(XLUMAJOR) $(DESTDIR)$(LIBDIR)/libxlutil.so
	$(INSTALL_DATA) libxlutil.a $(DESTDIR)$(LIBDIR)
	$(INSTALL_DATA) libxl.h _libxl_types.h libxl_uuid.h $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_DATA) bash-completion $(DESTDIR)$(BASH_COMPLETION_DIR)/xl.sh

.PHONY: clean
clean:
	$(RM) -f _*.h *.o *.so* *.a $(CLIENTS) $(DEPS)
	$(RM) -f _*.c *.pyc _libxl_paths.*.tmp
#	$(RM) -f $(AUTOSRCS) $(AUTOINCS)

distclean: clean

-include $(DEPS)
