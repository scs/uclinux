VER = busybox-1.12.1

export KBUILD_OUTPUT = $(ROOTDIR)/user/busybox/build-$(VER)

all: build-$(VER)/.config depmod.pl
	$(MAKE) -C build-$(VER)

# the uclinux-dist config gets updated a lot more than the busybox options,
# so dont bother updating the busybox config if none of the options have
# changed.  this will save time on pointless recompiling/relinking.
build-$(VER)/.config: $(ROOTDIR)/config/.config
	mkdir -p build-$(VER)
	sed -n -e '/CONFIG_USER_BUSYBOX_/s:CONFIG_USER_BUSYBOX_:CONFIG_:p' $< > $@.uclinux-dist.new
	set -e ; \
	if ! cmp -s $@.uclinux-dist.new $@.uclinux-dist.old ; then \
		cp $@.uclinux-dist.new $@.uclinux-dist.old ; \
		cp $@.uclinux-dist.old $@ ; \
		yes "" | $(MAKE) -C $(VER) oldconfig ; \
	fi

depmod.pl: $(VER)/examples/depmod.pl
	ln -sf $< $@

clean:
	rm -rf build*

bbdir = build-$(VER)/$(CONFIG_USER_BUSYBOX_PREFIX)
romfs:
	rm -rf $(bbdir)
	$(MAKE) -C build-$(VER) install
	-test -L $(ROMFSDIR)/sbin && mv $(bbdir)/sbin/* $(bbdir)/bin/ && rmdir $(bbdir)/sbin
	cp -pPR $(bbdir)/* $(ROMFSDIR)/

.PHONY: all clean romfs
