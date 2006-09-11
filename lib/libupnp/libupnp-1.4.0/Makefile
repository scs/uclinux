LIB_VER = libupnp-1.4.0

# To build BFLT format, need to set "--enable-shared=no"
all: static_upnp

shared_upnp:
	cd $(LIB_VER); \
	CC=bfin-uclinux-gcc CFLAGS="-mfdpic -fpic" LDFLAGS="-mfdpic" \
	./configure --host=bfin-linux --enable-samples; \
	make

static_upnp:
	cd $(LIB_VER); \
	CC=bfin-uclinux-gcc CFLAGS="-DBFIN" LDFLAGS="-Wl,-elf2flt" \
	./configure --host=bfin-linux --enable-shared=no --enable-samples; \
	make

clean distclean:
	if [ -e $(LIB_VER)/Makefile ] ; then \
		$(MAKE) -C $(LIB_VER) $@ || exit $$? ; \
	fi
