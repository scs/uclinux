#############################################################
#
# gnu mp (provides libraries)
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

GMP_SITE:=ftp://ftp.gnu.org/gnu/gmp/
GMP_SOURCE:=gmp-4.1.4.tar.gz
GMP_DIR:=$(BUILD_DIR)/gmp-4.1.4
GMP_BINARY:=libgmp.a

$(DL_DIR)/$(GMP_SOURCE):
	$(WGET) -P $(DL_DIR) $(GMP_SITE)/$(GMP_SOURCE)

gmp-source: $(DL_DIR)/$(GMP_SOURCE)

$(GMP_DIR)/.unpacked: $(DL_DIR)/$(GMP_SOURCE)
	zcat $(DL_DIR)/$(GMP_SOURCE) | tar -C $(BUILD_DIR) -xf -
	touch  $(GMP_DIR)/.unpacked

$(GMP_DIR)/.configured: $(GMP_DIR)/.unpacked
	(cd $(GMP_DIR); rm -rf config.cache; \
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
	touch  $(GMP_DIR)/.configured

$(STAGING_DIR)/lib/$(GMP_BINARY): $(GMP_DIR)/.configured
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
	-C $(GMP_DIR) install

$(TARGET_DIR)/lib/$(GMP_BINARY): $(STAGING_DIR)/lib/$(GMP_BINARY)
	cp -a $(STAGING_DIR)/lib/$(GMP_BINARY) $(TARGET_DIR)/lib/$(GMP_BINARY)

#gmp: uclibc $(TARGET_DIR)/lib/$(GMP_BINARY)
gmp: uclibc $(STAGING_DIR)/lib/$(GMP_BINARY)

gmp-clean:
	rm -f $(TARGET_DIR)/lib/$(GMP_BINARY)
	-$(MAKE) -C $(GMP_DIR) clean

gmp-dirclean:
	rm -rf $(GMP_DIR)
