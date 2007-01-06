CONFOPTS=

all: build/build
	$(MAKE) -C build "LIBS=$(CXXLIBS) -lpthread"

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; ac_cv_func_malloc_0_nonnull=yes CC="gcc -static" CXX="g++ -static" sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) build/src/iperf /bin/iperf
