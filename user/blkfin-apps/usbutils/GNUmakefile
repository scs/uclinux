all: Makefile
	$(MAKE) -f Makefile

Makefile:
	ac_cv_func_malloc_0_nonnull=yes \
	LDFLAGS="${LDFLAGS} -L$(ROOTDIR)/lib/libusb/.libs" \
	CPPFLAGS="${CPPFLAGS} -I$(ROOTDIR)/lib/libusb" \
	./configure --host=$(CONFIGURE_HOST) --prefix=/usr

%::
	if [ -f Makefile ] ; then $(MAKE) -f Makefile $@ || exit $$? ; fi

romfs:
	$(ROMFSINST) lsusb /bin/
	$(ROMFSINST) usb.ids /usr/share
