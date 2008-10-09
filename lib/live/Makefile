VER = live.2008.10.07

all: $(VER)/Makefile
	$(MAKE) -C $(VER)

	set -e ; \
	cd $(VER) ; \
	for l in UsageEnvironment liveMedia BasicUsageEnvironment groupsock ; do \
		install -D -m 644 $${l}/lib$${l}.a $(STAGEDIR)/usr/lib/lib$${l}.a ; \
		install -d -m 755 $(STAGEDIR)/usr/include/$${l} ; \
		install -m 644 $${l}/include/*h $(STAGEDIR)/usr/include/$${l}/ ; \
	done

	# create symlinks for stupid packages (like mplayer)
	ln -s $(ROOTDIR)/lib/live/$(VER) $(STAGEDIR)/usr/lib/live

$(VER)/Makefile:
	set -e ; \
	cd $(VER) ; \
	./genMakefiles $(CONFIGURE_HOST)

clean:
	[ ! -e $(VER)/Makefile ] || $(MAKE) -C $(VER) clean
	find $(VER) '(' -name Makefile -o -name '*.gdb' ')' -print0 | xargs -0 rm -f

romfs:

.PHONY: all clean romfs
