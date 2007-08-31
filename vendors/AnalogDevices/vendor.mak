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
# Allow people to create custom rules in vendor/AnalogDevices/<board>/
# without having to change the Makefile in the dist
#

-include Makefile.local
