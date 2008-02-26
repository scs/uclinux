VER = ethtool-1.8

all: build
	$(MAKE) -C build

build: Makefile
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	rm -rf build
	mkdir build
	(cd build; CC="$(CC) $(CFLAGS)" LDFLAGS="$(LDFLAGS)" LIBS="$(LDLIBS)" ../$(VER)/configure)

romfs:
	$(ROMFSINST) build/ethtool /bin/ethtool

clean:
	rm -rf build

