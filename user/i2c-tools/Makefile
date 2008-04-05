VER = i2c-tools-3.0.1

FLTFLAGS = -s 0x4000

all:
	$(MAKE) -C $(VER) CC=$(CC) CFLAGS="$(CFLAGS)"

clean:
	$(MAKE) -C $(VER) clean
	rm -f $(VER)/*/*.gdb

romfs:
	$(ROMFSINST) -d $(VER)/tools/i2cdetect /usr/bin/i2cdetect
	$(ROMFSINST) -d $(VER)/tools/i2cdump /usr/bin/i2cdump
	$(ROMFSINST) -d $(VER)/tools/i2cget /usr/bin/i2cget
	$(ROMFSINST) -d $(VER)/tools/i2cset /usr/bin/i2cset

.PHONY: all clean romfs
