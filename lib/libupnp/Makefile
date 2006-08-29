LIB_VER = libupnp-1.4.0

# To build BFLT format, need to set "--enable-shared=no"
all:
	cd $(LIB_VER); \
	make;	\
	cp $(LIB_VER)/upnp/.libs/libupnp.a ../;	\
	cp $(LIB_VER)/upnp/upnp_tv_ctrlpt ../; \
	cp $(LIB_VER)/upnp/upnp_tv_device ../

romfs:
# For static library, do nothing. For shared lib, cp the library to <romfs>/lib

clean:
	make -C $(LIB_VER) clean
	rm -f libupnp.a upnp_tv_ctrlpt upnp_tv_device
