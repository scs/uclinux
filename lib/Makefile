##############################################################################
#
#	Makefile -- Master makefile for all libraries.
#

.EXPORT_ALL_VARIABLES:

##############################################################################
#
# Include architecture specific build rules.
#

ifndef ROOTDIR
ROOTDIR=..
endif

UCLINUX_BUILD_LIB=1
include $(LINUX_CONFIG)
include $(CONFIG_CONFIG)
include $(ARCH_CONFIG)

##############################################################################
#
# always build these dir_
#
dir_y  = ../include $(LIBCDIR) ../include libnet
dir_n  =
dir_   =

ifeq ($(LIBCDIR),libc)
dir_y += libm
endif

#
# Add zlib if JFFS is needed
#
dir_$(CONFIG_JFFS_FS)          += zlib
dir_$(CONFIG_JFFS2_FS)         += zlib

#
#
# and build these if someone needs them
#
dir_$(CONFIG_LIB_FLEX)         += flex
dir_$(CONFIG_LIB_FLEX_FORCE)   += flex
dir_$(CONFIG_LIB_LIBAES)       += libaes
dir_$(CONFIG_LIB_LIBAES_FORCE) += libaes
dir_$(CONFIG_LIB_LIBDES)       += libdes
dir_$(CONFIG_LIB_LIBDES_FORCE) += libdes
dir_$(CONFIG_LIB_LIBSSL)       += libssl
dir_$(CONFIG_LIB_LIBSSL_FORCE) += libssl
dir_$(CONFIG_LIB_LIBGMP)       += libgmp
dir_$(CONFIG_LIB_LIBGMP_FORCE) += libgmp
dir_$(CONFIG_LIB_LIBG)         += libg
dir_$(CONFIG_LIB_LIBG_FORCE)   += libg
dir_$(CONFIG_LIB_LIBPAM)       += libpam
dir_$(CONFIG_LIB_LIBPAM_FORCE) += libpam
dir_$(CONFIG_LIB_LIBPCAP)      += libpcap
dir_$(CONFIG_LIB_LIBPCAP_FORCE)+= libpcap
dir_$(CONFIG_LIB_ZLIB)         += zlib
dir_$(CONFIG_LIB_ZLIB_FORCE)   += zlib
dir_$(CONFIG_LIB_LIBATM)       += libatm
dir_$(CONFIG_LIB_LIBATM_FORCE) += libatm
dir_$(CONFIG_LIB_LIBPNG)       += libpng
dir_$(CONFIG_LIB_LIBPNG_FORCE) += libpng
dir_$(CONFIG_LIB_LIBJPEG)      += libjpeg
dir_$(CONFIG_LIB_LIBJPEG_FORCE)+= libjpeg
dir_$(CONFIG_LIB_LIBUPNP)      += libupnp
dir_$(CONFIG_LIB_LIBUPNP_FORCE)+= libupnp
dir_$(CONFIG_LIB_STLPORT)      += STLport
dir_$(CONFIG_LIB_STLPORT_FORCE)+= STLport
dir_$(CONFIG_LIB_EXPAT)        += expat
dir_$(CONFIG_LIB_EXPAT_FORCE)  += expat
dir_$(CONFIG_LIB_LIBLDAP)      += libldap
dir_$(CONFIG_LIB_LIBLDAP_FORCE)+= libldap
dir_$(CONFIG_LIB_TINYTCL)      += ../user/tinytcl
dir_$(CONFIG_LIB_LIBCCMALLOC)  += libccmalloc
dir_$(CONFIG_LIB_ADNS_FORCE)   += adns
dir_$(CONFIG_LIB_LIBCRYPT_OLD) += libcrypt_old
dir_$(CONFIG_LIB_LIBCRYPT_OLD_FORCE) += libcrypt_old

# And build libraries in the prop directory last
dir_y += $(ROOTDIR)/prop

##############################################################################

all:
	for i in $(dir_y) ; do \
		[ ! -d $$i ] || make -C $$i || exit $$? ; \
		$(MAKE) make_links || exit $? ; \
	done

##############################################################################

romfs:
	for i in $(dir_y) ; do \
		[ ! -d $$i ] || make -C $$i romfs || exit $$? ; \
	done
	-$(STRIP) $(ROMFSDIR)/lib/*

##############################################################################

clean: clean_links
	-for i in $(dir_y) $(dir_n) $(dir_); do \
		[ ! -d $$i ] || make -C $$i clean ; \
	done

##############################################################################
#
# The libs we link into this directory
#
#
LINKLIBS=\
	$(ROOTDIR)/lib/$(LIBCDIR)/build/lib/crt*.o \
	$(ROOTDIR)/lib/$(LIBCDIR)/build/lib/*.gdb \
	$(ROOTDIR)/lib/$(LIBCDIR)/build/lib/*.so* \
	$(ROOTDIR)/lib/$(LIBCDIR)/build/lib/*.a \
	$(ROOTDIR)/lib/$(LIBCDIR)/build/crt*.o \
	$(ROOTDIR)/lib/$(LIBCDIR)/build/*.gdb \
	$(ROOTDIR)/lib/$(LIBCDIR)/build/*.so* \
	$(ROOTDIR)/lib/$(LIBCDIR)/build/*.a \
	$(ROOTDIR)/lib/$(LIBCDIR)/lib/crt*.o \
	$(ROOTDIR)/lib/$(LIBCDIR)/lib/*.gdb \
	$(ROOTDIR)/lib/$(LIBCDIR)/lib/*.so* \
	$(ROOTDIR)/lib/$(LIBCDIR)/lib/*.a \
	$(ROOTDIR)/lib/$(LIBCDIR)/crt*.o \
	$(ROOTDIR)/lib/$(LIBCDIR)/*.gdb \
	$(ROOTDIR)/lib/$(LIBCDIR)/*.so* \
	$(ROOTDIR)/lib/$(LIBCDIR)/*.a \
	$(ROOTDIR)/lib/libm/*.a \
	$(ROOTDIR)/lib/libnet/*.a \
	$(ROOTDIR)/lib/libdes/*.a \
	$(ROOTDIR)/lib/libaes/*.a \
	$(ROOTDIR)/lib/libpcap/*.a \
	$(ROOTDIR)/lib/libssl/*.so* $(ROOTDIR)/lib/libssl/*.a \
	$(ROOTDIR)/lib/zlib/libz.a \
	$(ROOTDIR)/lib/libatm/src/lib/*.so* $(ROOTDIR)/lib/libatm/src/lib/*.a \
	$(ROOTDIR)/lib/libcrypt_old/libcrypt_old.a \
	$(ROOTDIR)/lib/libldap/builddir/libraries/libldap/.libs/*.a \
	$(ROOTDIR)/lib/libldap/builddir/libraries/liblber/.libs/*.a \
	$(ROOTDIR)/prop/libsnapgear++/*.a $(ROOTDIR)/prop/libsnapgear++/*.so* \
	$(ROOTDIR)/prop/libsnapgear/*.a $(ROOTDIR)/prop/libsnapgear/*.so* \
	$(ROOTDIR)/user/tinytcl/*.a $(ROOTDIR)/user/tinytcl/*.so* \
	$(ROOTDIR)/prop/config/*.a $(ROOTDIR)/prop/config/*.so* \
	$(ROOTDIR)/prop/uberconfig/*.a $(ROOTDIR)/prop/uberconfig/*.so* \
	$(ROOTDIR)/prop/gccmapping/*.a $(ROOTDIR)/prop/gccmapping/*.so* \
	$(ROOTDIR)/lib/expat/*.a $(ROOTDIR)/lib/expat/*.so* \
	$(ROOTDIR)/lib/libupnp/upnp/bin/*.so* $(ROOTDIR)/lib/adns/src/libadns.a

##############################################################################

make_links: clean_links
	@echo "Making symlinks in lib/"
	@for p in $(LINKLIBS); do \
		for i in $$p; do \
			[ ! -e "$$i" ] && continue; \
			[ "`basename $$i`" = CVS ] && continue; \
			[ -L "./`basename $$i`" ] && continue; \
			ln -s $$i .; \
		done ; \
	done

clean_links:
	@-for i in *; do \
		[ "$$i" = "Makefile" ] && continue; \
		[ -L "$$i" ] || continue ; \
		case "`file -L $$i`" in \
		*directory*) ;; \
		*) rm -f $$i ;; \
		esac ; \
	done

##############################################################################
