OSIP2_FLAGS+=--disable-shared
OSIP2_FLAGS+=--enable-static

all:	Makefile
	make install

Makefile:
	./configure --host=bfin-uclinux --prefix=$(TEMPDIR) $(OSIP2_FLAGS) CC="$(CC)"

clean:
	make -i distclean
	find . -name '*.gdb' -print0 | xargs -0 rm -f

	
