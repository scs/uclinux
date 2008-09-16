NXLIB = nxlib-0.45
FLTK = fltk-1.1.8rc3

CONF_OPTS = \
	--x-includes=$$PWD/../nxlib-0.45/X11/include \
	--x-libraries=$$PWD/../nxlib-0.45

all: fltk 
	
fltk: $(FLTK)/makeinclude
	$(MAKE) -C $(FLTK)

$(FLTK)/makeinclude: nxlib
	find $(FLTK) -type f -print0 | xargs -0 touch -r $(FLTK)/configure
	set -e ; \
	cd $(FLTK) ; \
	./configure $(CONFIGURE_OPTS) $(CONF_OPTS)

nxlib: 
	$(MAKE) -C $(NXLIB)

clean:
	$(MAKE) -C $(FLTK) distclean
	$(MAKE) -C $(NXLIB) clean

romfs:	
	set -e; \
        cd $(NXLIB); \
        for l in `find -name '*.so'` ; do \
                $(ROMFSINST) -d $$l /usr/lib/$$l ; \
        done
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_NXLIB -d $(FLTK)/test/editor /usr/bin/editor
	
.PHONY: all clean romfs fltk nxlib
