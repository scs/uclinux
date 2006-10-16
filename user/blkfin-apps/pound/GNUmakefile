all: Makefile
	$(MAKE) -f Makefile

Makefile:
	./configure --host=$(CONFIGURE_HOST) --prefix=/usr --prefix=/usr/local \
		CFLAGS="$(CFLAGS) -I$(ROOTDIR)/lib/libssl/include" \
		LDFLAGS="$(LDFLAGS) -L$(ROOTDIR)/lib/libssl"

%::
	if [ -f Makefile ] ; then $(MAKE) -f Makefile $@ || exit $$? ; fi

