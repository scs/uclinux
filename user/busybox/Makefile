VER = busybox-1.9.1

all: $(VER)/.config depmod.pl $(VER)/Makefile.local
	$(MAKE) -C $(VER)

# the uclinux-dist config gets updated a lot more than the busybox options,
# so dont bother updating the busybox config if none of the options have
# changed.  this will save time on pointless recompiling/relinking.
$(VER)/.config: $(ROOTDIR)/config/.config
	sed -n -e '/CONFIG_USER_BUSYBOX_/s:CONFIG_USER_BUSYBOX_:CONFIG_:p' $< > $@.uclinux-dist.new
	set -e ; \
	if ! cmp -s $@.uclinux-dist.new $@.uclinux-dist.old ; then \
		cp $@.uclinux-dist.new $@.uclinux-dist.old ; \
		cp $@.uclinux-dist.old $@ ; \
		yes "" | $(MAKE) -C $(VER) oldconfig ; \
	fi

depmod.pl: $(VER)/examples/depmod.pl
	ln -sf $< $@

$(VER)/Makefile.local: Makefile.local
	cp -f $< $@

clean:
	rm -f depmod.pl
	rm -f $(VER)/Makefile.local
	rm -f $(VER)/.config.uclinux-dist*
	$(MAKE) -C $(VER) distclean

romfs:
	$(MAKE) -C $(VER) romfs

.PHONY: all clean romfs
