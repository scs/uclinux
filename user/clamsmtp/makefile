
CONFOPTS :=	--enable-dependency-tracking		\
		--sysconfdir=/etc/config

all: build/build
	$(MAKE) -C build

build/build: makefile
	@chmod u+x configure
	@rm -rf build
	@mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	@touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) build/src/clamsmtpd /bin/clamsmtpd
	$(ROMFSINST) doc/clamsmtpd.conf /etc/clamav/clamsmtpd.conf
