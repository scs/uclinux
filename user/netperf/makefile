CONFOPTS=

all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; ac_cv_func_setpgrp_void=yes sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) -e CONFIG_USER_NETPERF_NETPERF build/src/netperf /bin/netperf
	$(ROMFSINST) -e CONFIG_USER_NETPERF_NETSERVER build/src/netserver /bin/netserver
