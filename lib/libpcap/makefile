CONFOPTS = --with-pcap=linux --with-headers=$(ROOTDIR)/include
ifdef CONFIG_IPV6
CONFOPTS += --enable-ipv6
endif

all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
