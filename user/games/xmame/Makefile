VER = xmame-0.106

SYMLINKS = $(VER)/install-sh $(VER)/cab $(VER)/contrib $(VER)/doc

all: $(SYMLINKS)
	$(MAKE) -C $(VER) -f makefile.unix $@ -j8

clean:
	$(MAKE) -C $(VER) -f makefile.unix clean
	rm -f $(SYMLINKS)

$(SYMLINKS):
	ln -s src/unix/$(notdir $@) $@

romfs:
	$(ROMFSINST) -d $(VER)/xtiny.SDL /usr/bin/xtiny.SDL

.PHONY: all clean romfs
