
all:

include Makefile.conf

oldconfig: conf
	$(SCRIPTSDIR)/conf -o Kconfig

config: conf
	$(SCRIPTSDIR)/conf Kconfig

menuconfig: mconf
	$(SCRIPTSDIR)/mconf Kconfig

clean: confclean
	rm -f autoconf.h auto.conf .config .config.old

