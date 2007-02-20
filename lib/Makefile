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
dir_y  =
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
dir_$(CONFIG_LIB_DMALLOC)      += dmalloc
dir_$(CONFIG_LIB_DMALLOC_FORCE)+= dmalloc
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
dir_$(CONFIG_LIB_POPT)		+= popt
dir_$(CONFIG_LIB_MPFR)         += mpfr
dir_$(CONFIG_LIB_MPFR_FORCE)   += mpfr
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
dir_$(CONFIG_LIB_NCURSES)        += ncurses
dir_$(CONFIG_LIB_NCURSES_FORCE)  += ncurses
dir_$(CONFIG_LIB_READLINE)       += readline
dir_$(CONFIG_LIB_READLINE_FORCE) += readline
dir_$(CONFIG_LIB_LIBTOOL)        += libtool
dir_$(CONFIG_LIB_LIBTOOL_FORCE)  += libtool
dir_$(CONFIG_LIB_BFIN_GSM)       += blackfin-gsm
dir_$(CONFIG_LIB_LIBBFDSP)       += libbfdsp
dir_$(CONFIG_LIB_OSIP2)          += osip2
dir_$(CONFIG_LIB_OSIP2_FORCE)    += osip2
dir_$(CONFIG_LIB_SPEEX)          += speex
dir_$(CONFIG_LIB_SPEEX_FORCE)    += speex
dir_$(CONFIG_LIB_LIBUSB)         += libusb
dir_$(CONFIG_LIB_LIBUSB_FORCE)   += libusb
dir_$(CONFIG_LIB_ALSA_LIB)       += alsa-lib
dir_$(CONFIG_LIB_ALSA_LIB_FORCE) += alsa-lib
dir_$(CONFIG_LIB_FAAD2)          +=faad2
dir_$(CONFIG_LIB_FAAD2_FORCE)    +=faad2
dir_$(CONFIG_LIB_FLAC)           +=flac
dir_$(CONFIG_LIB_FLAC_FORCE)     +=flac
dir_$(CONFIG_LIB_TREMOR)         +=tremor
dir_$(CONFIG_LIB_TREMOR_FORCE)   +=tremor
dir_$(CONFIG_LIB_LIBAO)          +=libao-0.8.6
dir_$(CONFIG_LIB_LIBAO_FORCE)    +=libao-0.8.6
dir_$(CONFIG_LIB_LIBAUDIO)       +=libaudio
dir_$(CONFIG_LIB_LIBAUDIO_FORCE) +=libaudio
dir_$(CONFIG_LIB_LIBMAD)         +=libmad
dir_$(CONFIG_LIB_LIBMAD_FORCE)   +=libmad
dir_$(CONFIG_LIB_LIBID3TAG)      +=libid3tag
dir_$(CONFIG_LIB_LIBID3TAG_FORCE)+=libid3tag
dir_$(CONFIG_LIB_BLUEZ)          += bluez-libs
dir_$(CONFIG_LIB_BLUEZ_FORCE)    += bluez-libs

# And build libraries in the prop directory last
dir_y += $(wildcard $(ROOTDIR)/prop)

##############################################################################

all:
	for i in $(dir_y) ; do make -C $$i || exit $$? ; done
	-cd $(STAGEDIR) && sed -i "/^libdir=/s:=.*:='$(STAGEDIR)/usr/lib':" ./usr/lib/*.la

##############################################################################

romfs:
	for i in $(dir_y) ; do \
		[ ! -d $$i ] || make -C $$i romfs || exit $$? ; \
	done
	-for i in $(ROMFSDIR)/lib/* ; do \
		if [ -f $$i -a ! -h $$i ] ; then \
			$(STRIP) $$i; \
		fi; \
	done

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
