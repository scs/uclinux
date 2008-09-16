############################################################################
#
# Allow people to quickly sync their staging directory with the actual
# toolchain as this will allow them to transparently build external apps
# against libraries from uClinux-dist
#

SYSROOT_LIBDIR = $(shell bfin-linux-uclibc-gcc $(CPUFLAGS) -print-file-name=libc.a | sed 's:/usr/lib/libc.a$$::')
ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
vendor_staging_install:
	cp -a $(STAGEDIR)/* $(SYSROOT_LIBDIR)/
else
vendor_staging_install:
	@printf "\nlibs_install: this only works for FDPIC ELF toolchains\n\n"
	@false
endif

############################################################################
#
# Copy the FDPIC ELF and Shared FLAT libraries as requested/needed according
# to the user configuration options
#

romfs.shared.libs:
ifeq ($(CONFIG_INSTALL_ELF_SHARED_LIBS),y)
	set -e; \
	t=`bfin-linux-uclibc-gcc $(CPUFLAGS) -print-file-name=libc.a`; \
	t=`dirname $$t`/../..; \
	for i in $$t/lib/*so*; do \
		bn=`basename $$i`; \
		if [ -f $$i ] ; then \
			$(ROMFSINST) -p 755 $$i /lib/$$bn; \
		fi; \
	done; \
	for i in $$t/lib/*so*; do \
		if [ -h $$i -a -e $$i ] ; then \
			j=`readlink $$i`; \
			$(ROMFSINST) -s \
				`basename $$j` \
				/lib/`basename $$i`; \
		fi; \
	done; \
	if type bfin-linux-uclibc-ldconfig >/dev/null 2>&1; then \
		bfin-linux-uclibc-ldconfig -r $(ROMFSDIR); \
	fi
endif
ifeq ($(CONFIG_INSTALL_FLAT_SHARED_LIBS),y)
	set -e; \
	t=`bfin-uclinux-gcc $(CPUFLAGS) -mid-shared-library -print-file-name=libc`; \
	if [ -f $$t -a ! -h $$t ] ; then \
		$(ROMFSINST) -p 755 $$t /lib/lib1.so; \
	fi
endif

############################################################################
#
# Allow people to create custom rules in vendor/AnalogDevices/<board>/
# without having to change the Makefile in the dist
#

-include Makefile.local
