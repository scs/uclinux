
CONFIG_LANGUAGE ?= english
ifeq ($(CONFIG_LANGUAGE),)
CONFIG_LANGUAGE=english
endif

ifneq ($(findstring english,$(CONFIG_LANGUAGE)),)
SQUID_LANG:=English
endif
ifneq ($(findstring japanese,$(CONFIG_LANGUAGE)),)
SQUID_LANG:=Japanese
endif
ifneq ($(findstring chinese,$(CONFIG_LANGUAGE)),)
SQUID_LANG:=Simplify_Chinese
endif


all: build
	$(MAKE) -C build

romfs:
	$(MAKE) -C build $@

build: makefile
	chmod a+x configure
	rm -rf build
	mkdir build
	( \
		cd build; \
		CC="$(CC) $(CFLAGS)" LDFLAGS="$(LDFLAGS)" LIBS="$(LDLIBS)"		\
			../configure --prefix= --build=i386-redhat-linux		\
				--with-headers=$(ROOTDIR)/$(LINUXDIR)/include		\
				--target=$(CROSS_COMPILE:-=)				\
				--sysconfdir=/etc/config				\
				--datadir=/etc --libexecdir=/bin			\
				--enable-err-languages="$(sort $(SQUID_LANG) English)"	\
				--enable-default-err-language=$(SQUID_LANG)		\
				--enable-linux-netfilter --disable-ident-lookups	\
				--enable-dependency-tracking				\
				--enable-icap-support					\
	)

clean:
	rm -rf build

