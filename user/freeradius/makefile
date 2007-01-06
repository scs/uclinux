.EXPORT_ALL_VARIABLES:

CONFOPTS = --disable-shared --with-raddbdir=/etc/config
CONFOPTS += --without-threads --without-snmp
CONFOPTS += --with-openssl-includes=$(ROOTDIR)/include/openssl
CONFOPTS += --with-openssl-libraries=$(ROOTDIR)/lib

CFLAGS += -I$(ROOTDIR)/include -I$(ROOTDIR)/include/openssl

all: .build
	$(MAKE) -f Makefile all

.build: makefile
	./configure $(CONFIGURE_OPTS) $(CONFOPTS)
	touch .build

.IGNORE: clean
clean:
	make -f Makefile distclean
	@rm -f .build

romfs:

%: .build
	$(MAKE) -f Makefile $@

