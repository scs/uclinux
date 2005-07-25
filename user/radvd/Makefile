all: build
	$(MAKE) -C build

build: Makefile
	rm -rf build
	mkdir build
	(cd build; CC="$(CC) $(CFLAGS)" LDFLAGS="$(LDFLAGS)" LIBS="$(LDLIBS)" RANLIB=$(RANLIB) ../configure --host=$(CROSS_COMPILE:-=))

romfs:
	$(ROMFSINST) etc /etc
	$(ROMFSINST) -e CONFIG_USER_RADVD_RADVD build/radvd /bin/radvd
	$(ROMFSINST) -e CONFIG_USER_RADVD_RADVD build/radvdump /bin/radvdump
clean:
	rm -rf build
