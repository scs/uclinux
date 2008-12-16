VER = qt-embedded-linux-opensource-src-4.4.3
URL = ftp://ftp.trolltech.no/qt/source/$(VER).tar.gz

USE_ECHO = $(shell test "$(CONFIG_$(1))" = "y" && echo "$(2)" || echo "$(3)")

ifeq ($(CONFIGURE_SHARED_ENABLE),--enable-shared)
CONF_SHARED_OPT = -shared
CONF_XPLATFORM  = qws/linux-bfin-fdpic-g++
else
CONF_SHARED_OPT = -static
CONF_XPLATFORM  = qws/linux-bfin-flat-g++
endif

CONFIG_QT_DEPTH ?= 8,16,24,32
CONF_OPTS = \
	-confirm-license \
	-prefix /usr \
	-embedded bfin \
	-xplatform $(CONF_XPLATFORM) \
	-little-endian \
	$(CONF_SHARED_OPT) \
	-depths $(CONFIG_QT_DEPTH) \
	-no-qt3support \
	-nomake docs \
	$(call USE_ECHO,LIB_QT_EXAMPLES,,-nomake demos -nomake examples) \
	-nomake translations \
	-system-zlib \
	-qt-gif \
	$(call USE_ECHO,LIB_LIBTIFF,-system-libtiff,-no-libtiff) \
	$(call USE_ECHO,LIB_LIBSSL,-openssl,-no-openssl) \
	$(call USE_ECHO,LIB_LIBPNG,-system-libpng,-no-libpng) \
	$(call USE_ECHO,LIB_LIBMNG,-system-libmng,-no-libmng) \
	$(call USE_ECHO,LIB_LIBJPEG,-system-libjpeg,-no-libjpeg) \
	-no-nis \
	-no-cups \
	-no-dbus \
	$(call USE_ECHO,LIB_FREETYPE,-system-freetype,-no-freetype) \
	$(call USE_ECHO,LIB_GLIB,-glib,-no-glib)

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER) INSTALL_ROOT=$(STAGEDIR) install

$(DOWNLOADDIR)/$(VER).tar.gz:
	wget $(URI) -P $(DOWNLOADDIR)

$(VER)/.unpacked: $(DOWNLOADDIR)/$(VER).tar.gz
	tar xf $<
	for p in $$PWD/patches/*.patch ; do cd $(VER) && patch -p1 < $$p || exit $$? ; done
	touch $(VER)/.unpacked

build-$(VER)/Makefile: $(VER)/.unpacked
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	unset CC CXX CFLAGS CXXFLAGS LDFLAGS ; \
	../$(VER)/configure $(CONF_OPTS)

old_$(VER)/Makefile:
	cd $(VER) && \
	./configure \
		-embedded bfin \
		-depths 16 \
		-shared \
		-prefix /home/dave/Blackfin/qt-4.2.2-TC0702 \
		-qt-mouse-tslib \
		-no-separate-debug-info \
		-no-cups \
		-no-nis \
		-DQT_NO_SOUND \
		-DQT_NO_QWS_MULTIPROCESS \
		-I/home/dave/Blackfin/SVN/uclinux-dist-trunk/lib/tslib-1.0/src \
		-L/home/dave/Blackfin/SVN/uclinux-dist-trunk/lib/tslib-1.0/build/src/.libs \
		-xplatform qws/linux-bfin-g++

clean:
	rm -rf build*

romfs:
ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
	set -e ; \
	for l in $$(cd $(STAGEDIR)/usr/lib ; echo libQt*.so.?) ; do \
		$(ROMFSINST) -d $(STAGEDIR)/usr/lib/$$l /usr/lib/$$l ; \
	done
endif

.PHONY: all clean romfs
