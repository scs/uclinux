FLTFLAGS=-s 20000

all: Makefile
	$(MAKE) -f Makefile

Makefile:
	./configure --with-ssl=$(ROOTDIR)/lib/libssl --host=$(CONFIGURE_HOST) \
		--prefix=/usr/local --disable-super \
		LDFLAGS="$(LDFLAGS) -L$(ROOTDIR)/lib/libssl"

%::
	if [ -f Makefile ] ; then $(MAKE) -f Makefile $@ || exit $$? ; fi

