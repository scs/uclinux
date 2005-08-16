
all: build
	$(MAKE) -C build

build: Makefile
	rm -rf build
	mkdir build
	(cd build; CC="$(CC) $(CFLAGS)" LDFLAGS="$(LDFLAGS)" LIBS="$(LDLIBS)" RANLIB=$(RANLIB) ../configure --host=$(ARCH)-linux)

romfs:
	$(ROMFSINST) build/xsupplicant /bin/xsupplicant

clean:
	rm -rf build

