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
ROOTDIR=$(PWD)/..
endif

UCLINUX_BUILD_LIB=1
-include $(LINUX_CONFIG)
-include $(CONFIG_CONFIG)
-include $(ARCH_CONFIG)
-include $(MODULES_CONFIG)

##############################################################################
#
# always build these dir_
#
dir_1_y  = $(LIBCDIR)
dir_1_n  =
dir_1_   =

ifeq ($(LIBCDIR),libc)
dir_2_y += libm libcrypt_old
dir_2_n +=
dir_2_  +=
endif

#
# and build these if someone needs them
#
dir_3_$(CONFIG_LIB_FLEX)         += flex
dir_3_$(CONFIG_LIB_LIBAES)       += libaes
dir_3_$(CONFIG_LIB_LIBDES)       += libdes
dir_3_$(CONFIG_LIB_LIBSSL)       += libssl
dir_3_$(CONFIG_LIB_LIBGMP)       += libgmp
dir_3_$(CONFIG_LIB_LIBG)         += libg
dir_3_$(CONFIG_LIB_LIBPAM)       += libpam
dir_3_$(CONFIG_LIB_LIBPCAP)      += libpcap
dir_3_$(CONFIG_LIB_ZLIB)         += zlib
dir_3_$(CONFIG_LIB_LIBBZ2)       += libbzip2
dir_3_$(CONFIG_LIB_LIBATM)       += libatm
dir_3_$(CONFIG_LIB_LIBNET)       += Libnet
dir_3_$(CONFIG_LIB_LIBNETOLD)    += libnet
dir_3_$(CONFIG_LIB_LIBJPEG)      += libjpeg
dir_3_$(CONFIG_LIB_LIBUPNP)      += libupnp
dir_3_$(CONFIG_LIB_STLPORT)      += STLport
dir_3_$(CONFIG_LIB_EXPAT)        += expat
dir_3_$(CONFIG_LIB_LIBLDAP)      += libldap
dir_3_$(CONFIG_LIB_TINYTCL)      += ../user/tinytcl
dir_3_$(CONFIG_LIB_LIBCCMALLOC)  += libccmalloc
dir_3_$(CONFIG_LIB_ARES)         += libares
dir_3_$(CONFIG_LIB_LIBIDN)       += libidn
dir_4_$(CONFIG_LIB_LIBCURL)      += libcurl
dir_3_$(CONFIG_LIB_LIBCRYPT_OLD) += libcrypt_old
dir_3_$(CONFIG_LIB_LIBLZO)       += lzo
dir_3_$(CONFIG_LIB_LIBPCRE)      += pcre
dir_3_$(CONFIG_LIB_LIBLZMA)      += liblzma
dir_3_$(CONFIG_LIB_OSIP2)        += libosip2
dir_3_$(CONFIG_LIB_LIBEFENCE)    += libefence
dir_3_$(CONFIG_LIB_TERMCAP)      += termcap
dir_3_$(CONFIG_LIB_LIBSYSFS)     += sysfsutils
dir_3_$(CONFIG_LIB_LIBNL)        += libnl
dir_3_$(CONFIG_LIB_NFNETLINK)    += libnfnetlink
dir_3_$(CONFIG_USER_TCL_LIBTCL)  += ../user/tcl
dir_3_$(CONFIG_LIB_LIBIBERTY)    += libiberty
dir_3_$(CONFIG_LIB_BFD)          += bfd
dir_3_$(CONFIG_LIB_POPT)         += popt
dir_4_$(CONFIG_LIB_PWLIB)        += pwlib
dir_4_$(CONFIG_LIB_NETFILTER_LOG)+= libnetfilter_log
dir_4_$(CONFIG_LIB_NETFILTER_CONNTRACK) += libnetfilter_conntrack
dir_4_$(CONFIG_LIB_LIBPNG)       += libpng
dir_5_$(CONFIG_LIB_LIBOPENH323)  += libopenh323

-include Makefile.local

# And build libraries in the prop directory last
dir_9_y += $(wildcard $(ROOTDIR)/prop)

DIRS_NUM = 1 2 3 4 5 6 7 8 9
DIRS_y   = $(foreach n,$(DIRS_NUM),$(sort $(dir_$(n)_y)))
DIRS_all = $(foreach n,$(DIRS_NUM),$(sort $(dir_$(n)_y) $(dir_$(n)_n) $(dir_$(n)_)))

##############################################################################

SET_STAGEDIR = \
	(cd $(STAGEDIR); \
	chmod 755 ./usr/lib/lib*.so*; \
	chmod 644 ./usr/lib/lib*.la ./usr/lib/lib*.a; \
	sed -i -e "/^libdir=/s:=.*:='$(STAGEDIR)/usr/lib':" -e "/^dependency_libs=/s: /usr/lib/: $(STAGEDIR)/usr/lib/:g" ./usr/lib/*.la; \
	sed -i "/^prefix=/s:=.*:='$(STAGEDIR)/usr':" ./usr/lib/pkgconfig/*.pc ./usr/bin/*-config; \
	true)

all:
	[ -z "$(dir_1_y)" ] || $(MAKE) -j$(HOST_NCPU) $(sort $(dir_1_y)) || exit $$?
	[ -z "$(dir_1_y)" ] || $(SET_STAGEDIR)
	[ -z "$(dir_2_y)" ] || $(MAKE) -j$(HOST_NCPU) $(sort $(dir_2_y)) || exit $$?
	[ -z "$(dir_2_y)" ] || $(SET_STAGEDIR)
	[ -z "$(dir_3_y)" ] || $(MAKE) -j$(HOST_NCPU) $(sort $(dir_3_y)) || exit $$?
	[ -z "$(dir_3_y)" ] || $(SET_STAGEDIR)
	[ -z "$(dir_4_y)" ] || $(MAKE) -j$(HOST_NCPU) $(sort $(dir_4_y)) || exit $$?
	[ -z "$(dir_4_y)" ] || $(SET_STAGEDIR)
	[ -z "$(dir_5_y)" ] || $(MAKE) -j$(HOST_NCPU) $(sort $(dir_5_y)) || exit $$?
	[ -z "$(dir_5_y)" ] || $(SET_STAGEDIR)
	[ -z "$(dir_6_y)" ] || $(MAKE) -j$(HOST_NCPU) $(sort $(dir_6_y)) || exit $$?
	[ -z "$(dir_6_y)" ] || $(SET_STAGEDIR)
	[ -z "$(dir_7_y)" ] || $(MAKE) -j$(HOST_NCPU) $(sort $(dir_7_y)) || exit $$?
	[ -z "$(dir_7_y)" ] || $(SET_STAGEDIR)
	[ -z "$(dir_8_y)" ] || $(MAKE) -j$(HOST_NCPU) $(sort $(dir_8_y)) || exit $$?
	[ -z "$(dir_8_y)" ] || $(SET_STAGEDIR)
	[ -z "$(dir_9_y)" ] || $(MAKE) -j$(HOST_NCPU) $(sort $(dir_9_y)) || exit $$?
	[ -z "$(dir_9_y)" ] || $(SET_STAGEDIR)

# the actual dir target
.PHONY: $(DIRS_y)
$(DIRS_y):
	[ ! -d "$@" ] || ( touch $@/.sgbuilt_lib && $(MAKE) -C $@ ) || exit $$?

%_only:
	touch $(@:_only=)/.sgbuilt_lib && $(MAKE) -C $(@:_only=) -j$(HOST_NCPU)

%_clean:
	$(MAKE) -C $(@:_clean=) clean; rm -f $(@:_clean=)/.sgbuilt_lib; true

%_romfs:
	$(MAKE) -j1 -C $(@:_romfs=) romfs

##############################################################################

romfs:
	for i in $(DIRS_y) ; do \
		[ ! -d $$i ] || $(MAKE) -C $$i romfs || exit $$? ; \
	done

##############################################################################

clean:
	-for i in $(DIRS_all); do \
		if [ -f $$i/.sgbuilt_lib ]; then \
			$(MAKE) -C $$i clean ; \
			rm -f $$i/.sgbuilt_lib; \
		fi; \
	done

##############################################################################
#
# The libs we link into this directory
#
#
LINKLIBS=\
	$(ROOTDIR)/lib/libjpeg/*.a \
	$(ROOTDIR)/lib/libpng/*.a \
	$(ROOTDIR)/lib/libm/*.a \
	$(ROOTDIR)/lib/libatm/src/lib/.libs/*.a \
	$(ROOTDIR)/lib/libdes/*.a \
	$(ROOTDIR)/lib/libaes/*.a \
	$(ROOTDIR)/lib/libpam/build/libpam*/.libs/*.a \
	$(ROOTDIR)/lib/libpam/build/libpam*/.libs/*.so \
	$(ROOTDIR)/lib/libpcap/build/*.a \
	$(ROOTDIR)/lib/libnet/*.a \
	$(ROOTDIR)/lib/liblzma/*.a \
	$(ROOTDIR)/lib/libares/build/*.a \
	$(ROOTDIR)/lib/libidn/build/lib/.libs/libidn.a \
	$(ROOTDIR)/lib/libcurl/build/lib/.libs/libcurl.a \
	$(ROOTDIR)/lib/libcurl/build/lib/.libs/libcurl.so \
	$(ROOTDIR)/lib/libssl/build/*.so* \
	$(ROOTDIR)/lib/libssl/build/*.a \
	$(ROOTDIR)/lib/zlib/libz.a* \
	$(ROOTDIR)/lib/zlib/libz.so* \
	$(ROOTDIR)/lib/libbzip2/libbz2.a* \
	$(ROOTDIR)/lib/libbzip2/libbz2.so* \
	$(ROOTDIR)/lib/libatm/src/lib/*.so* $(ROOTDIR)/lib/libatm/src/lib/*.a \
	$(ROOTDIR)/lib/libcrypt_old/libcrypt_old.a \
	$(ROOTDIR)/lib/libldap/builddir/libraries/libldap/.libs/*.a \
	$(ROOTDIR)/lib/libldap/builddir/libraries/liblber/.libs/*.a \
	$(ROOTDIR)/lib/pcre/builddir/.libs/*.a \
	$(ROOTDIR)/prop/acld/libacld.a \
	$(ROOTDIR)/prop/libsnapgear++/*.a $(ROOTDIR)/prop/libsnapgear++/*.so* \
	$(ROOTDIR)/prop/libsnapgear/*.a $(ROOTDIR)/prop/libsnapgear/*.so* \
	$(ROOTDIR)/user/tinytcl/*.a $(ROOTDIR)/user/tinytcl/*.a* \
	$(ROOTDIR)/user/tinytcl/*.a $(ROOTDIR)/user/tinytcl/*.so* \
	$(ROOTDIR)/user/tcl/build/*.a \
	$(ROOTDIR)/prop/config/*.a $(ROOTDIR)/prop/config/*.so* \
	$(ROOTDIR)/prop/uberconfig/*.a $(ROOTDIR)/prop/uberconfig/*.so* \
	$(ROOTDIR)/prop/gccmapping/*.a $(ROOTDIR)/prop/gccmapping/*.so* \
	$(ROOTDIR)/lib/expat/*.a $(ROOTDIR)/lib/expat/*.so* \
	$(ROOTDIR)/lib/libupnp/upnp/bin/*.so* $(ROOTDIR)/lib/adns/src/libadns.a \
	$(ROOTDIR)/lib/flex/build/*.a \
	$(ROOTDIR)/lib/libgmp/build/install/lib/*.a \
	$(ROOTDIR)/lib/lzo/build/src/.libs/*.a \
	$(ROOTDIR)/lib/osip2/build/install/lib/*.a \
	$(ROOTDIR)/prop/libsscep/*.a \
	$(ROOTDIR)/prop/statsd/*.a \
	$(ROOTDIR)/prop/statsd/*.so \
	$(ROOTDIR)/lib/libefence/*.a \
	$(ROOTDIR)/lib/termcap/*.a \
	$(ROOTDIR)/lib/sysfsutils/build/lib/.libs/*.a \
	$(ROOTDIR)/lib/libnl/lib/*.a* \
	$(ROOTDIR)/lib/libnl/lib/*.so* \
	$(ROOTDIR)/lib/libnfnetlink/build/src/.libs/*.a* \
	$(ROOTDIR)/lib/libnfnetlink/build/src/.libs/*.so* \
	$(ROOTDIR)/lib/libnfnetlink/build/libnfnetlink.pc \
	$(ROOTDIR)/lib/libnetfilter_conntrack/build/src/.libs/*.a* \
	$(ROOTDIR)/lib/libnetfilter_conntrack/build/src/.libs/*.so* \
	$(ROOTDIR)/lib/libnetfilter_conntrack/build/libnetfilter_conntrack.pc \
	$(ROOTDIR)/lib/libnetfilter_log/build/src/.libs/*.a* \
	$(ROOTDIR)/lib/libnetfilter_log/build/src/.libs/*.so* \
	$(ROOTDIR)/lib/libnetfilter_log/build/libnetfilter_log.pc \
	$(ROOTDIR)/lib/libiberty/build/*.a \
	$(ROOTDIR)/lib/bfd/build/*.a \
	$(ROOTDIR)/lib/popt/build/.libs/*.a \
	$(ROOTDIR)/lib/STLport/lib/*.a \
	$(ROOTDIR)/lib/STLport/lib/*.so \
	$(ROOTDIR)/prop/librep/librep.a

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
		[ "$$i" = "Kconfig" ] && continue; \
		[ -L "$$i" ] || continue ; \
		case "`file -L $$i`" in \
		*directory*) ;; \
		*) rm -f $$i ;; \
		esac ; \
	done

##############################################################################

prune:
	-for i in $(DIRS_all) ; do \
		found=0; \
		for j in $(sort $(DIRS_y)) ; do \
			if [ $$i = $$j ]; then \
				found=1; \
			fi; \
		done; \
		if [ $$found = 0 ]; then \
			rm -fr $$i; \
		fi; \
	done
##############################################################################
