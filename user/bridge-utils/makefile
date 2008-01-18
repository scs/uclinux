CONFOPTS=--with-linux=$(ROOTDIR)/$(LINUXDIR)

all: Makefile
	$(MAKE) -f Makefile

Makefile:
	sh configure $(CONFIGURE_OPTS) $(CONFOPTS)

clean:
	$(MAKE) -f Makefile distclean
	rm -f Makefile

romfs:
	$(ROMFSINST) brctl/brctl /bin/brctl
