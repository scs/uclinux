#############################################################
#
# alsa-lib (provides alsa libraries)
#
#############################################################
# Copyright (C) 2001-2003 by Erik Andersen <andersen@codepoet.org>
# Copyright (C) 2002 by Tim Riker <Tim@Rikers.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Library General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU Library General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA

ALSA-LIB_SITE:=ftp://ftp.alsa-project.org/pub/lib/
ALSA-LIB_SOURCE:=alsa-lib-1.0.9rc2.tar.bz2
ALSA-LIB_DIR:=$(BUILD_DIR)/alsa-lib-1.0.9rc2
ALSA-LIB_BINARY:=libasound.so.2.0.0

$(DL_DIR)/$(ALSA-LIB_SOURCE):
	$(WGET) -P $(DL_DIR) $(ALSA-LIB_SITE)/$(ALSA-LIB_SOURCE)

alsa-lib-source: $(DL_DIR)/$(ALSA-LIB_SOURCE)

$(ALSA-LIB_DIR)/.unpacked: $(DL_DIR)/$(ALSA-LIB_SOURCE)
	bzcat $(DL_DIR)/$(ALSA-LIB_SOURCE) | tar -C $(BUILD_DIR) -xf -
	touch  $(ALSA-LIB_DIR)/.unpacked

$(ALSA-LIB_DIR)/.configured: $(ALSA-LIB_DIR)/.unpacked
	(cd $(ALSA-LIB_DIR); rm -rf config.cache; \
		$(TARGET_CONFIGURE_OPTS) CFLAGS="$(TARGET_CFLAGS)" \
		./configure \
		--target=$(GNU_TARGET_NAME) \
		--host=$(GNU_TARGET_NAME) \
		--build=$(GNU_HOST_NAME) \
		--prefix=/usr \
		--exec-prefix=/usr \
		--bindir=/usr/bin \
		--sbindir=/usr/sbin \
		--libexecdir=/usr/lib \
		--sysconfdir=/etc \
		--datadir=/usr/share \
		--localstatedir=/tmp \
		--mandir=/usr/man \
		--infodir=/usr/info \
		--with-debug=no \
		$(DISABLE_NLS) \
		--disable-timesync \
	);
	touch  $(ALSA-LIB_DIR)/.configured

$(STAGING_DIR)/lib/$(ALSA-LIB_BINARY): $(ALSA-LIB_DIR)/.configured
	$(MAKE) CROSS_COMPILE="$(TARGET_CROSS)" prefix="$(STAGING_DIR)" \
	exec_prefix=$(STAGING_DIR) \
	bindir=$(STAGING_DIR)/bin \
	sbindir=$(STAGING_DIR)/sbin \
	libexecdir=$(STAGING_DIR)/libexec \
	datadir=$(STAGING_DIR)/share \
	sysconfdir=$(STAGING_DIR)/etc \
	sharedstatedir=$(STAGING_DIR)/com \
	localstatedir=$(STAGING_DIR)/var \
	libdir=$(STAGING_DIR)/lib \
	includedir=$(STAGING_DIR)/include \
	oldincludedir=$(STAGING_DIR)/include \
	infodir=$(STAGING_DIR)/info \
	mandir=$(STAGING_DIR)/man \
	-C $(ALSA-LIB_DIR) install

$(TARGET_DIR)/lib/$(ALSA-LIB_BINARY): $(STAGING_DIR)/lib/$(ALSA-LIB_BINARY)
	mkdir -p $(TARGET_DIR)/usr/share/alsa/ || true
	cp $(ALSA-LIB_DIR)/src/conf/alsa.conf $(TARGET_DIR)/usr/share/alsa/
	mknod /dev/snd/controlC0 c 116 0 || true
	mknod /dev/snd/controlC1 c 116 32 || true
	mknod /dev/snd/hwC0D0 c 116 4 || true
	mknod /dev/snd/hwC1D0 c 116 36 || true
	cp -a $(STAGING_DIR)/lib/libasound.so.2 $(TARGET_DIR)/lib/libasound.so.2
	cp -a $(STAGING_DIR)/lib/libasound.so $(TARGET_DIR)/lib/libasound.so
	cp -a $(STAGING_DIR)/lib/$(ALSA-LIB_BINARY) $(TARGET_DIR)/lib/$(ALSA-LIB_BINARY)

alsa-lib: uclibc $(TARGET_DIR)/lib/$(ALSA-LIB_BINARY)

alsa-lib-clean:
	rm -f $(TARGET_DIR)/lib/$(ALSA-LIB_BINARY)
	-$(MAKE) -C $(ALSA-LIB_DIR) clean

alsa-lib-dirclean:
	rm -rf $(ALSA-LIB_DIR)
