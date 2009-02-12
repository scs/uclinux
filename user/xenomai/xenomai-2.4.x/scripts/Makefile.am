bin_SCRIPTS=xeno-config xeno-load xeno-test xeno-info

install-exec-local:
	@if test -r $(srcdir)/postinstall.sh ; then \
	   echo "Running post-install script..." ;\
	   $(srcdir)/postinstall.sh ; \
	fi

EXTRA_DIST = bootstrap prepare-kernel.sh xeno-info \
	Kconfig.frag Modules.frag defconfig.frag \
	help_from_kconfig.pl $(wildcard postinstall.sh)
