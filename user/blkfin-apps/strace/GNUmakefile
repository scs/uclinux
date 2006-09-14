all: Makefile
	$(MAKE) -f Makefile

Makefile:
	./configure --host=$(CONFIGURE_HOST) --prefix=$(ROMFSDIR)/usr

romfs:
	$(ROMFSINST) strace /bin/
	$(ROMFSINST) -e CONFIG_USER_PERL_PERL strace-graph /bin/

%::
	if [ -f Makefile ] ; then $(MAKE) -f Makefile $@ || exit $$? ; fi
