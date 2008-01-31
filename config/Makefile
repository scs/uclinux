
all:

include Makefile.conf

oldconfig: conf
	$(SCRIPTSDIR)/conf -o Kconfig

config: conf
	$(SCRIPTSDIR)/conf Kconfig

menuconfig: mconf
	$(SCRIPTSDIR)/mconf Kconfig

gconfig: gconf
	$(SCRIPTSDIR)/gconf Kconfig

qconfig: qconf
	$(SCRIPTSDIR)/qconf Kconfig

xconfig: qconfig

clean: confclean
	rm -f autoconf.h auto.conf .config .config.old

