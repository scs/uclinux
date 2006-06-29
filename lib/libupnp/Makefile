LIB_VER = libupnp-1.4.0

# To build BFLT format, need to set "--enable-shared=no"
all: static_upnp

shared_upnp:
	cd $(LIB_VER); \
	CC=bfin-uclinux-gcc CFLAGS="-mfdpic -fpic" LDFLAGS="-mfdpic" \
	./configure --host=bfin-uclinux --enable-samples; \
	make
	cp $(LIB_VER)/upnp/.libs/libupnp.so .

static_upnp:
	cd $(LIB_VER); \
	CC=bfin-uclinux-gcc CFLAGS="-DBFIN" LDFLAGS="-Wl,-elf2flt" \
	./configure --host=bfin-linux --enable-shared=no --enable-samples; \
	make
	cp $(LIB_VER)/upnp/.libs/libupnp.a .

romfs:
# For static library, do nothing. For shared lib, cp the library to <romfs>/lib

clean:
	make -C $(LIB_VER) distclean
	rm -f libupnp.a
