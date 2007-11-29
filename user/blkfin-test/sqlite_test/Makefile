ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),)
LDLIBS += $(shell $(PKG_CONFIG) sqlite3 --libs --static)
else
LDLIBS += $(shell $(PKG_CONFIG) sqlite3 --libs)
endif

all: sqlite_test

clean: 
	rm -f *.o sqlite_test sqlite_test.o.* sqlite_test.gdb *~

romfs:
	$(ROMFSINST) /bin/sqlite_test 
	$(ROMFSINST) /usr/wishlist.sql
