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
dir_3_$(CONFIG_LIB_FLEX_FORCE)   += flex
dir_3_$(CONFIG_LIB_LIBAES)       += libaes
dir_3_$(CONFIG_LIB_LIBAES_FORCE) += libaes
dir_3_$(CONFIG_LIB_LIBDES)       += libdes
dir_3_$(CONFIG_LIB_LIBDES_FORCE) += libdes
dir_3_$(CONFIG_LIB_LIBSSL)       += libssl
dir_3_$(CONFIG_LIB_LIBSSL_FORCE) += libssl
dir_3_$(CONFIG_LIB_LIBGMP)       += libgmp
dir_3_$(CONFIG_LIB_LIBGMP_FORCE) += libgmp
dir_3_$(CONFIG_LIB_LIBG)         += libg
dir_3_$(CONFIG_LIB_LIBG_FORCE)   += libg
dir_3_$(CONFIG_LIB_LIBPAM)       += libpam
dir_3_$(CONFIG_LIB_LIBPAM_FORCE) += libpam
dir_3_$(CONFIG_LIB_LIBPCAP)      += libpcap
dir_3_$(CONFIG_LIB_LIBPCAP_FORCE)+= libpcap
dir_3_$(CONFIG_LIB_ZLIB)         += zlib
dir_3_$(CONFIG_LIB_ZLIB_FORCE)   += zlib
dir_3_$(CONFIG_LIB_LIBBZ2)       += libbzip2
dir_3_$(CONFIG_LIB_LIBBZ2_FORCE) += libbzip2
dir_3_$(CONFIG_LIB_LIBATM)       += libatm
dir_3_$(CONFIG_LIB_LIBATM_FORCE) += libatm
dir_3_$(CONFIG_LIB_LIBNET)       += Libnet
dir_3_$(CONFIG_LIB_LIBNET_FORCE) += Libnet
dir_3_$(CONFIG_LIB_LIBNETOLD)    += libnet
dir_3_$(CONFIG_LIB_LIBJPEG)      += libjpeg
dir_3_$(CONFIG_LIB_LIBJPEG_FORCE)+= libjpeg
dir_3_$(CONFIG_LIB_LIBUPNP)      += libupnp
dir_3_$(CONFIG_LIB_LIBUPNP_FORCE)+= libupnp
dir_3_$(CONFIG_LIB_STLPORT)      += STLport
dir_3_$(CONFIG_LIB_STLPORT_FORCE)+= STLport
dir_3_$(CONFIG_LIB_EXPAT)        += expat
dir_3_$(CONFIG_LIB_EXPAT_FORCE)  += expat
dir_3_$(CONFIG_LIB_LIBLDAP)      += libldap
dir_3_$(CONFIG_LIB_LIBLDAP_FORCE)+= libldap
dir_3_$(CONFIG_LIB_TINYTCL)      += ../user/tinytcl
dir_3_$(CONFIG_LIB_LIBCCMALLOC)  += libccmalloc
dir_3_$(CONFIG_LIB_ADNS_FORCE)   += adns
dir_3_$(CONFIG_LIB_ARES)         += libares
dir_3_$(CONFIG_LIB_ARES_FORCE)   += libares
dir_3_$(CONFIG_LIB_LIBIDN)       += libidn
dir_3_$(CONFIG_LIB_LIBIDN_FORCE) += libidn
dir_4_$(CONFIG_LIB_LIBCURL)      += libcurl
dir_4_$(CONFIG_LIB_LIBCURL_FORCE)+= libcurl
dir_3_$(CONFIG_LIB_LIBCRYPT_OLD) += libcrypt_old
dir_3_$(CONFIG_LIB_LIBCRYPT_OLD_FORCE) += libcrypt_old
dir_3_$(CONFIG_LIB_LIBLZO)       += lzo
dir_3_$(CONFIG_LIB_LIBLZO_FORCE) += lzo
dir_3_$(CONFIG_LIB_LIBPCRE)      += pcre
dir_3_$(CONFIG_LIB_LIBPCRE_FORCE)+= pcre
dir_3_$(CONFIG_LIB_LIBLZMA)      += liblzma
dir_3_$(CONFIG_LIB_LIBLZMA_FORCE)+= liblzma
dir_3_$(CONFIG_LIB_OSIP2)        += libosip2
dir_3_$(CONFIG_LIB_OSIP2_FORCE)  += libosip2
dir_3_$(CONFIG_LIB_LIBEFENCE)    += libefence
dir_3_$(CONFIG_LIB_LIBEFENCE_FORCE) += libefence
dir_3_$(CONFIG_LIB_TERMCAP)      += termcap
dir_3_$(CONFIG_LIB_TERMCAP_FORCE)+= termcap
dir_3_$(CONFIG_LIB_LIBSYSFS)     += sysfsutils
dir_3_$(CONFIG_LIB_LIBSYSFS_FORCE) += sysfsutils
dir_3_$(CONFIG_LIB_NFNETLINK)    += libnfnetlink
dir_4_$(CONFIG_LIB_NETFILTER_LOG)+= libnetfilter_log
dir_4_$(CONFIG_LIB_NETFILTER_CONNTRACK) += libnetfilter_conntrack
dir_4_$(CONFIG_LIB_LIBPNG)       += libpng
dir_4_$(CONFIG_LIB_LIBPNG_FORCE) += libpng

-include Makefile.local

# And build libraries in the prop directory last
dir_9_y += $(wildcard $(ROOTDIR)/prop)

DIRS_y   = $(foreach n,1 2 3 4 5 6 7 8 9,$(sort $(dir_$(n)_y)))
DIRS_all = $(foreach n,1 2 3 4 5 6 7 8 9,$(sort $(dir_$(n)_y) $(dir_$(n)_n) $(dir_$(n)_)))

##############################################################################

SET_STAGEDIR = \
	(cd $(STAGEDIR); \
	chmod 755 ./usr/lib/lib*.so*; \
	chmod 644 ./usr/lib/lib*.la ./usr/lib/lib*.a; \
	sed -i "/^libdir=/s:=.*:='$(STAGEDIR)/usr/lib':" ./usr/lib/*.la; \
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
	$(MAKE) -C $@

%_only:
	touch $(@:_only=)/.sgbuilt_lib && $(MAKE) -C $(@:_only=) -j$(HOST_NCPU)

%_clean:
	$(MAKE) -C $(@:_clean=) clean; rm -f $(@:_clean=)/.sgbuilt_lib; true

##############################################################################

romfs:
	for i in $(DIRS_y) ; do \
		[ ! -d $$i ] || $(MAKE) -C $$i romfs || exit $$? ; \
	done
	-for i in $(ROMFSDIR)/lib/* $(ROMFSDIR)/usr/lib/* ; do \
		if [ -f $$i -a ! -h $$i ] ; then \
			$(STRIP) $$i; \
		fi; \
	done

##############################################################################

clean:
	-for i in $(DIRS_all); do \
		[ ! -d $$i ] || make -C $$i clean ; \
	done
