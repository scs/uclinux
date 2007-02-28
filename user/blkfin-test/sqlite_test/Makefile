
all: 
	$(CC) $(CFLAGS) $(LDFLAGS) -o sqlite_test sqlite_test.c -I../../blkfin-apps/sqlite-3.2.6/DESTDIR/usr/include/ -L../../blkfin-apps/sqlite-3.2.6/DESTDIR/usr/lib -lsqlite3 $(LDLIBS) 

clean: 
	rm -f *.o sqlite_test sqlite_test.o.* sqlite_test.gdb *~

romfs:
	$(ROMFSINST) /bin/sqlite_test 
	$(ROMFSINST) /usr/wishlist.sql
