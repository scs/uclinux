ACLOCAL_AMFLAGS=-I config

SUDO=sudo

SUBDIRS = src include config @XENO_MAYBE_DOCDIR@ scripts

EXTRA_DIST = CREDITS README.INSTALL TROUBLESHOOTING ksrc examples \
            debian/changelog debian/control debian/copyright debian/rules \
            debian/prepare-patch.sh debian/xenomai.postinst debian/xenomai.postrm

dist-hook:
	rm -fr `find $(distdir) -name '.svn' -o -name CVS  -o -name '.#*' \
                -o -name '*~' -o -name autom4te.cache`
	test -e $(srcdir)/doc || rm -rf $(distdir)/doc

dev devices:
        $(mkinstalldirs) $(DESTDIR)/dev ; \
	@if test x`id -u` = x0; then \
           sudo= ; \
        else if test \! "x`type $(SUDO)`" = x ; then \
           echo "sudo found (sudo is $(SUDO)), testing it..." ; \
           $(SUDO) sh -c "( mknod $(DESTDIR)/dev/dummy c 150 0 && rm -f $(DESTDIR)/dev/dummy )" && \
           sudo="$(SUDO)" || { \
echo '*** Warning: you are not super-user and sudo does not work, real-time\
devices' ; \
echo '*** nodes will not be created.' ; \
echo '*** If you do not create these devices by hand, Xenomai test programs\
will not' ; \
echo '*** work.' ; \
echo '*** To create these devices please run "make devices" with super-user' ; \
echo '*** privileges.' ; \
             exit 0 ; } ; \
           echo 'sudo is working.' ; \
           fi ; \
        fi ; \
        if test -r $(DESTDIR)/etc/udev/udev.rules ; then \
           for f in $(srcdir)/ksrc/nucleus/udev/*.rules ; do \
           b=`basename $$f` ; \
           grep -q Xenomai:`basename $$b .rules` $(DESTDIR)/etc/udev/udev.rules || \
           $$sudo sh -c "( echo ; cat $$f ) >> $(DESTDIR)/etc/udev/udev.rules" ; \
           done ; \
	fi ; \
	for n in `seq 0 31` ; do \
           f="$(DESTDIR)/dev/rtp$$n" ; \
           if test \! -c $$f ; then \
              $$sudo mknod -m 666 $$f c 150 $$n ; \
           fi ; \
        done ; \
        if test \! -c $(DESTDIR)/dev/rtheap ; then \
          $$sudo mknod -m 666 $(DESTDIR)/dev/rtheap c 10 254 ; \
        fi

install-exec-local: devices

install-user:
	$(MAKE) SUDO=false install

if XENO_BUILD_LINUX
if MAINTAINER_MODE
linux/%: linux/.xenomai-prepared FORCE
	$(top_srcdir)/scripts/prepare-kernel.sh \
             --adeos="$(ADEOS_PATCH)" --linux=linux \
	     --arch=$(XENO_LINUX_ARCH) && \
	cross=`expr "$(CC)" : '\(.*\)gcc' || :` && \
	cd linux && $(MAKE) $* \
		ARCH=$(XENO_LINUX_ARCH) CC="$(CC)" CROSS_COMPILE=$$cross

linux/all: linux/.xenomai-prepared FORCE
	$(top_srcdir)/scripts/prepare-kernel.sh \
             --adeos="$(ADEOS_PATCH)" --linux=linux \
	     --arch=$(XENO_LINUX_ARCH) && \
	cross=`expr "$(CC)" : '\(.*\)gcc' || :` && \
	cd linux && $(MAKE) $(XENO_LINUX_ALL_TARGETS) \
		ARCH=$(XENO_LINUX_ARCH) CC="$(CC)" CROSS_COMPILE=$$cross

else
linux/%: linux/.xenomai-prepared FORCE
	cross=`expr "$(CC)" : '\(.*\)gcc' || :` && \
	cd linux && $(MAKE) $* \
		ARCH=$(XENO_LINUX_ARCH) CC="$(CC)" CROSS_COMPILE=$$cross

linux/all: linux/.xenomai-prepared FORCE
	cross=`expr "$(CC)" : '\(.*\)gcc' || :` && \
	cd linux && $(MAKE) $(XENO_LINUX_ALL_TARGETS) \
		ARCH=$(XENO_LINUX_ARCH) CC="$(CC)" CROSS_COMPILE=$$cross
endif

linux/.xenomai-prepared: config.status
	./config.status linux

.PHONY: FORCE

linux/install: linux/all
	@targets=modules_install ; \
	sudo=; if test x`id -u` != x0 && test \! "x`type $(SUDO)`" = x && \
	$(SUDO) true ; then sudo=$(SUDO) ; targets="$$targets install" ; fi && \
	$(mkinstalldirs) $(DESTDIR) && \
	$$sudo $(mkinstalldirs) $(DESTDIR)/boot && \
	cross=`expr "$(CC)" : '\(.*\)gcc' || :` && \
	cd linux && $$sudo $(MAKE) $$targets \
           ARCH=$(XENO_LINUX_ARCH) CC="$(CC)" CROSS_COMPILE=$$cross \
           INSTALL_PATH=$(DESTDIR)/boot \
           INSTALL_MOD_PATH=$(DESTDIR)

# For architectures that do not support the install target, provide our own
# installation target that simply copy the kernel image and System.map.
linux/install_image: linux/all
	sudo=; if test x`id -u` != x0 && test \! "x`type $(SUDO)`" = x && \
	$(SUDO) true ; then sudo=$(SUDO) ; fi && \
	$(mkinstalldirs) $(DESTDIR) && \
	$$sudo $(mkinstalldirs) $(DESTDIR)/boot && \
	cross=`expr "$(CC)" : '\(.*\)gcc' || :` && \
	cd linux && $$sudo $(MAKE) modules_install \
           ARCH=$(XENO_LINUX_ARCH) CC="$(CC)" CROSS_COMPILE=$$cross \
           INSTALL_MOD_PATH=$(DESTDIR) && \
	$$sudo cp $(XENO_LINUX_IMAGE) System.map $(DESTDIR)/boot

distclean-linux:
	@test -e linux/.config && \
		mv linux/.config linux/.config.saved.xenomai ; \
	$(MAKE) linux/distclean ; \
	test -e linux/.config.saved.xenomai && \
		mv linux/.config.saved.xenomai linux/.config

config oldconfig mconfig menuconfig gconfig xconfig:
	$(MAKE) linux/$@

all-recursive: linux/all

clean-recursive: linux/clean

distclean-recursive: distclean-linux

install-recursive: linux/$(XENO_LINUX_INSTALL_TARGET)
endif
