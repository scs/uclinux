CONFOPTS =

all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	find . -type f -print0 | xargs -0 touch -r configure
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
