VER = tcpdump-3.9.2

CONFOPTS = --with-crypto --disable-smb
ifdef CONFIG_IPV6
CONFOPTS += --enable-ipv6
endif

all: build/build
	$(MAKE) -C build

build/build:
	rm -rf build
	mkdir build
	(cd build; sh ../$(VER)/configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) build/tcpdump /bin/tcpdump
