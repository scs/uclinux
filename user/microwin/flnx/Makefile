VER = flnx-0.18

CONF_OPTS = \
	--with-microwin=$$PWD/../../src

all: $(VER)/makeinclude
	$(MAKE) -C $(VER) install prefix=$(STAGEDIR)/usr

$(VER)/makeinclude:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	cd $(VER) ; \
	./configure $(CONFIGURE_OPTS) $(CONF_OPTS)

clean:
	$(MAKE) -C $(VER) distclean

romfs:

.PHONY: all clean romfs
