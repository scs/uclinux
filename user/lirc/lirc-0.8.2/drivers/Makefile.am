## $Id: Makefile.am,v 5.29 2007/05/26 13:30:51 lirc Exp $

## Process this file with automake to produce Makefile.in 

## here the correct driver is substituted in by the configure script
## (or empty for none)

EXTRA_DIST = lirc.h kcompat.h Makefile.kernel Makefile.common

DIST_SUBDIRS = lirc_atiusb \
	lirc_bt829 \
	lirc_cmdir \
	lirc_dev \
	lirc_gpio \
	lirc_i2c \
	lirc_igorplugusb \
	lirc_imon \
	lirc_it87 \
	lirc_mceusb \
	lirc_mceusb2 \
	lirc_parallel \
	lirc_sasem \
	lirc_serial \
	lirc_sir \
	lirc_streamzap \
	lirc_ttusbir

SUBDIRS = @lirc_driver@

CLEANFILES = *~

if SANDBOXED
else
install-exec-local: mklink mkdev
uninstall-local: rmlink mkdev
endif

mklink:
	test "@irtty@" = "" || test -L $(DESTDIR)$(devdir)/lirc || ($(mkinstalldirs) $(DESTDIR)$(devdir) && cd `dirname $(DESTDIR)@irtty@` && $(LN_S) `basename @irtty@` lirc)

rmlink:
	-test "@irtty@" = "" || $(RM) $(DESTDIR)$(devdir)/lirc

mkdev:
	test "@driver@" != "mediafocusI" || test -c $(DESTDIR)$(devdir)/lirc || ($(mkinstalldirs) $(DESTDIR)$(devdir) && @mknod@ $(DESTDIR)$(devdir)/lirc c @lirc_major@ 0)

rmdev:
	-test "@driver@" != "mediafocusI" || test -c $(DESTDIR)$(devdir)/lirc || $(RM) $(DESTDIR)$(devdir)/lirc
