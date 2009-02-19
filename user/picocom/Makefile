VER = picocom-1.4
URL = http://efault.net/npat/hacks/picocom/dist/$(VER).tar.gz

all:
	$(MAKE) -C $(VER) picocom

clean:
	$(MAKE) -C $(VER) distclean
	rm -f $(VER)/picocom.gdb

romfs:
	$(ROMFSINST) $(VER)/picocom /bin/picocom

.PHONY: all clean romfs
