VER = busybox-1.4.1

all %:
	ln -sf $(VER)/examples/depmod.pl
	cp -f Makefile.local $(VER)/
	$(MAKE) -C $(VER) $@
