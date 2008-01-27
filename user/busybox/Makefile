VER = busybox-1.9.0

all %:
	ln -sf $(VER)/examples/depmod.pl
	cp -f Makefile.local $(VER)/
	$(MAKE) -C $(VER) $@
