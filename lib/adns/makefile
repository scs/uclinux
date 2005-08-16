#
# Build using configure.
#

all: build/config.cache
	$(MAKE) MAKE="$(MAKE) -f Makefile"

romfs: build/config.cache
	$(MAKE) MAKE="$(MAKE) -f Makefile " $@

build/config.cache: makefile
#	export CFLAGS="$(VENDOR_CFLAGS) -DEMBED -O2"; \
	unset LDFLAGS; 
	./configure --with-headers=$(ROOTDIR)/include

#	chmod u+x configure; \
	mkdir build; \
	cd build; 


clean:
	$(MAKE) MAKE="$(MAKE) -f Makefile" clean
