VER = lzo-2.02

CONFOPTS =

all: build/build
	$(MAKE) -C build

build/build: Makefile
	rm -rf build
	mkdir build
	(cd build; sh ../$(VER)/configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
