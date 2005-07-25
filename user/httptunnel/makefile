.EXPORT_ALL_VARIABLES:

CONFIGURE_TARGET := $(strip $(subst -, ,$(CROSS)))
CONFIGURE_TARGET := $(word 1,$(CONFIGURE_TARGET))-$(word 2,$(CONFIGURE_TARGET))
CONFIGURE_SETTINGS := --prefix= --exec-prefix=/bin			\
		--includedir=$(ROOTDIR)/$(LINUXDIR)/include		\
		--bindir=/bin --datadir=/etc				\
		--build=i386-redhat-linux --host=$(CONFIGURE_TARGET)	\
		--cache-file=config.cache

silly_first_rule_thingy: Makefile
	make -f Makefile

Makefile:
	unset CC CFLAGS LDFLAGS && ./configure $(CONFIGURE_SETTINGS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_HTTPTUNNEL_CLIENT /bin/htc
	$(ROMFSINST) -e CONFIG_USER_HTTPTUNNEL_SERVER /bin/hts

clean: Makefile
	make -f Makefile distclean

%: Makefile
	make -f Makefile $@
