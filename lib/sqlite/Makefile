VER = sqlite-3.6.12
URL = http://sqlite.org/$(VER).tar.gz

CONF_OPTS = --disable-tcl

FLTFLAGS = -s 32000

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/sqlite3 /usr/bin/sqlite3
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libsqlite3.so.0 /usr/lib/libsqlite3.so.0
