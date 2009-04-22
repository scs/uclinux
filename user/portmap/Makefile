VER = portmap_6.0

export NO_TCP_WRAPPER = disabled
export NO_PIE = disabled

all:
	$(MAKE) -C $(VER)

romfs:
	$(ROMFSINST) -e CONFIG_USER_PORTMAP_PORTMAP $(VER)/portmap /bin/portmap
	$(ROMFSINST) -e CONFIG_USER_PORTMAP_PMAP_DUMP $(VER)/pmap_dump /bin/pmap_dump
	$(ROMFSINST) -e CONFIG_USER_PORTMAP_PMAP_SET $(VER)/pmap_set /bin/pmap_set

clean:
	$(MAKE) -C $(VER) clean
	rm -f $(VER)/*.gdb

.PHONY: all clean romfs
