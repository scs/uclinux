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
dir_3_$(CONFIG_LIB_LIBCURL)      += libcurl
dir_3_$(CONFIG_LIB_LIBCURL_FORCE)+= libcurl
dir_3_$(CONFIG_LIB_LIBCRYPT_OLD) += libcrypt_old
dir_3_$(CONFIG_LIB_LIBCRYPT_OLD_FORCE) += libcrypt_old
dir_3_$(CONFIG_LIB_LIBLZO)       += lzo
dir_3_$(CONFIG_LIB_LIBLZO_FORCE) += lzo
dir_3_$(CONFIG_LIB_LIBPCRE)      += pcre
dir_3_$(CONFIG_LIB_LIBPCRE_FORCE)+= pcre
dir_3_$(CONFIG_LIB_LIBLZMA)      += liblzma
dir_3_$(CONFIG_LIB_LIBLZMA_FORCE)+= liblzma
dir_3_$(CONFIG_LIB_OSIP2)        += osip2
dir_3_$(CONFIG_LIB_OSIP2_FORCE)    += osip2
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

#
# Blackfin additions
#
dir_3_$(CONFIG_LIB_DMALLOC)          += dmalloc
dir_3_$(CONFIG_LIB_DMALLOC_FORCE)    += dmalloc
dir_3_$(CONFIG_LIB_POPT)             += popt
dir_3_$(CONFIG_LIB_POPT_FORCE)       += popt
dir_3_$(CONFIG_LIB_MPFR)             += mpfr
dir_3_$(CONFIG_LIB_MPFR_FORCE)       += mpfr
dir_3_$(CONFIG_LIB_NCURSES)          += ncurses
dir_3_$(CONFIG_LIB_NCURSES_FORCE)    += ncurses
dir_3_$(CONFIG_LIB_READLINE)         += readline
dir_3_$(CONFIG_LIB_READLINE_FORCE)   += readline
dir_3_$(CONFIG_LIB_LIBTOOL)          += libtool
dir_3_$(CONFIG_LIB_LIBTOOL_FORCE)    += libtool
dir_3_$(CONFIG_LIB_BFIN_GSM)         += blackfin-gsm
dir_3_$(CONFIG_LIB_LIBBFDSP)         += libbfdsp
dir_3_$(CONFIG_LIB_SPEEX)            += speex
dir_3_$(CONFIG_LIB_SPEEX_FORCE)      += speex
dir_3_$(CONFIG_LIB_LIBUSB)           += libusb
dir_3_$(CONFIG_LIB_LIBUSB_FORCE)     += libusb
dir_3_$(CONFIG_LIB_ALSA_LIB)         += alsa-lib
dir_3_$(CONFIG_LIB_ALSA_LIB_FORCE)   += alsa-lib
dir_3_$(CONFIG_LIB_FAAD2)            += faad2
dir_3_$(CONFIG_LIB_FAAD2_FORCE)      += faad2
dir_3_$(CONFIG_LIB_FLAC)             += flac
dir_3_$(CONFIG_LIB_FLAC_FORCE)       += flac
dir_3_$(CONFIG_LIB_TREMOR)           += tremor
dir_3_$(CONFIG_LIB_TREMOR_FORCE)     += tremor
dir_3_$(CONFIG_LIB_LIBAO)            += libao-0.8.6
dir_3_$(CONFIG_LIB_LIBAO_FORCE)      += libao-0.8.6
dir_3_$(CONFIG_LIB_LIBAUDIO)         += libaudio
dir_3_$(CONFIG_LIB_LIBAUDIO_FORCE)   += libaudio
dir_3_$(CONFIG_LIB_LIBMAD)           += libmad
dir_3_$(CONFIG_LIB_LIBMAD_FORCE)     += libmad
dir_3_$(CONFIG_LIB_LIBID3TAG)        += libid3tag
dir_3_$(CONFIG_LIB_LIBID3TAG_FORCE)  += libid3tag
dir_3_$(CONFIG_LIB_BLUEZ)            += bluez-libs
dir_3_$(CONFIG_LIB_BLUEZ_FORCE)      += bluez-libs
dir_3_$(CONFIG_LIB_TSLIB)            += tslib-1.0
dir_3_$(CONFIG_LIB_TSLIB_FORCE)      += tslib-1.0
dir_3_$(CONFIG_LIB_LIBIPOD)          += libipod
dir_3_$(CONFIG_LIB_LIBIPOD_FORCE)    += libipod
dir_3_$(CONFIG_LIB_LIBICONV)         += libiconv
dir_3_$(CONFIG_LIB_LIBICONV_FORCE)   += libiconv
dir_3_$(CONFIG_LIB_LIBMPEG2)         += mpeg2dec
dir_3_$(CONFIG_LIB_LIBMPEG2_FORCE)   += mpeg2dec
dir_3_$(CONFIG_LIB_FFMPEG)           += ffmpeg
dir_3_$(CONFIG_LIB_FFMPEG_FORCE)     += ffmpeg

# And build libraries in the prop directory last
dir_5_y += $(wildcard $(ROOTDIR)/prop)

DIRS_y   = $(foreach n,1 2 3 4 5,$(sort $(dir_$(n)_y)))
DIRS_all = $(foreach n,1 2 3 4 5,$(sort $(dir_$(n)_y) $(dir_$(n)_n) $(dir_$(n)_)))

##############################################################################

all:
	[ -z "$(dir_1_y)" ] || $(MAKE) -j$(HOST_NCPU) $(sort $(dir_1_y)) || exit $$?
	[ -z "$(dir_2_y)" ] || $(MAKE) -j$(HOST_NCPU) $(sort $(dir_2_y)) || exit $$?
	[ -z "$(dir_3_y)" ] || $(MAKE) -j$(HOST_NCPU) $(sort $(dir_3_y)) || exit $$?
	[ -z "$(dir_4_y)" ] || $(MAKE) -j$(HOST_NCPU) $(sort $(dir_4_y)) || exit $$?
	[ -z "$(dir_5_y)" ] || $(MAKE) -j$(HOST_NCPU) $(sort $(dir_5_y)) || exit $$?
	-cd $(STAGEDIR) && sed -i "/^libdir=/s:=.*:='$(STAGEDIR)/usr/lib':" ./usr/lib/*.la
	-cd $(STAGEDIR) && sed -i "/^prefix=/s:=.*:='$(STAGEDIR)/usr':" ./usr/lib/pkgconfig/*.pc

# the actual dir target
.PHONY: $(DIRS_y)
$(DIRS_y):
	$(MAKE) -C $@

##############################################################################

romfs:
	for i in $(DIRS_y) ; do \
		[ ! -d $$i ] || $(MAKE) -C $$i romfs || exit $$? ; \
	done
	-for i in $(ROMFSDIR)/lib/* ; do \
		if [ -f $$i -a ! -h $$i ] ; then \
			$(STRIP) $$i; \
		fi; \
	done

##############################################################################

clean:
	-for i in $(DIRS_all); do \
		[ ! -d $$i ] || make -C $$i clean ; \
	done
