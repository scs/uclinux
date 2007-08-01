LDLIBS += -lsqlite3

all: sqlite_test

clean: 
	rm -f *.o sqlite_test sqlite_test.o.* sqlite_test.gdb *~

romfs:
	$(ROMFSINST) /bin/sqlite_test 
	$(ROMFSINST) /usr/wishlist.sql
