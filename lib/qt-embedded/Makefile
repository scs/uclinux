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
	-plugindir /usr/lib/qt \
	-datadir /usr/share/qt \
	-translationdir /usr/share/qt/translations \
	-sysconfdir /etc \
	-examplesdir /usr/qt/examples \
	-demosdir /usr/qt/demos \
	\
	-embedded bfin \
	-xplatform $(CONF_XPLATFORM) \
	-little-endian \
	\
	$(CONF_SHARED_OPT) \
	-depths $(CONFIG_QT_DEPTH) \
	-no-qt3support \
	$(call USE_ECHO,LIB_QT_WEBKIT,-webkit,-no-webkit) \
	\
	$(call USE_ECHO,LIB_QT_EXAMPLES,,-nomake demos -nomake docs -nomake examples) \
	-nomake translations

# QT requires zlib
CONF_OPTS += \
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
	$(call USE_ECHO,LIB_GLIB,-glib,-no-glib) \
	-no-sql-sqlite2 \
	$(call USE_ECHO,LIB_SQLITE,-system-sqlite,-no-sql-sqlite)

# ahi/hybrid - non-Blackfin PDAs
# svgalib - x86-only display driver
CONF_OPTS += \
	$(call USE_ECHO,LIB_DIRECTFB,-plugin-gfx-directfb,) \
	$(call USE_ECHO,FB,-qt-gfx-linuxfb,-no-gfx-linuxfb) \
	$(call USE_ECHO,LIB_QT_QVFB,-qt-gfx-qvfb,-no-gfx-qvfb) \
	-plugin-gfx-transformed \
	-plugin-gfx-vnc

# sl5000/vr41xx/yopy - non-Blackfin PDAs
CONF_OPTS += \
	-no-kbd-sl5000 -no-kbd-vr41xx -no-kbd-yopy \
	$(call USE_ECHO,LIB_QT_QVFB,-qt-kbd-qvfb,-no-kbd-qvfb) \
	$(call USE_ECHO,VT,-qt-kbd-tty,-no-kbd-tty) \
	$(call USE_ECHO,USB,-qt-kbd-usb,-no-kbd-usb)

# vr41xx/yopy - non-Blackfin PDAs
# linuxtp - old style touchpad (/dev/ts)
CONF_OPTS += \
	-no-mouse-bus -no-mouse-linuxtp -no-mouse-vr41xx -no-mouse-yopy \
	$(call USE_ECHO,LIB_QT_QVFB,-qt-mouse-qvfb,-no-mouse-qvfb) \
	$(call USE_ECHO,LIB_TSLIB,-qt-mouse-tslib,-no-mouse-tslib)

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER) INSTALL_ROOT=$(STAGEDIR) install
	cp qmake-wrapper $(ROOTDIR)/tools/$(CROSS_COMPILE)qmake
	sed -i "s:@STAGEDIR@:$(STAGEDIR):" $(ROOTDIR)/tools/$(CROSS_COMPILE)qmake

include $(ROOTDIR)/tools/download.mk

build-$(VER)/Makefile: $(VER)/.unpacked
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	unset CC CXX CFLAGS CXXFLAGS LDFLAGS ; \
	../$(VER)/configure $(CONF_OPTS)

clean:
	rm -rf build*
	rm -rf \
		$(STAGEDIR)/usr/lib/libQt* \
		$(STAGEDIR)/usr/qt \
		$(STAGEDIR)/usr/lib/qt \
		$(STAGEDIR)/usr/share/qt

romfs:
ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
	set -e ; \
	for l in $$(cd $(STAGEDIR)/usr/lib ; echo libQt*.so.?) ; do \
		$(ROMFSINST) -d $(STAGEDIR)/usr/lib/$$l /usr/lib/$$l ; \
	done
	$(ROMFSINST) -d $(STAGEDIR)/usr/lib/qt /usr/lib/qt
endif

	mkdir -p $(ROMFSDIR)/usr/lib/fonts
	cp $(STAGEDIR)/usr/lib/fonts/fixed_*.qpf $(STAGEDIR)/usr/lib/fonts/helvetica_*.qpf $(ROMFSDIR)/usr/lib/fonts/

ifeq (0,1) # this installs 13megs ... make people pick demos themselves
ifeq ($(CONFIG_LIB_QT_EXAMPLES),y)
	rm -rf $(ROMFSDIR)/usr/qt
	mkdir -p $(ROMFSDIR)/usr/qt
	cp -r $(STAGEDIR)/usr/qt/* $(ROMFSDIR)/usr/qt/
	find $(ROMFSDIR)/usr/qt/ \
		'(' \
			-name '*.demo' -o \
			-name '*.[ch]' -o \
			-name '*.pro' -o \
			-name '*.qrc' -o \
			-name README \
		')' -print0 | xargs -0 rm -f
endif
endif

#	$(ROMFSINST) -d $(STAGEDIR)/usr/share/qt/translations /usr/share/qt/translations

.PHONY: all clean romfs
