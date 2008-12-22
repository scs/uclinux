VER = sqlite-3.6.7
URL = http://sqlite.org/$(VER).tar.gz

CONF_OPTS = --disable-tcl

FLTFLAGS = -s 32000

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) $(STAGEDIR)/usr/bin/sqlite3 /bin/sqlite3
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libsqlite3.so.0 /lib/
