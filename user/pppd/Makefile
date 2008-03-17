VER = ppp-2.4.4

_MAKE = $(MAKE) \
	CC=$(CC) \
	COPTS="$(CFLAGS) -DNOMMU" \
	LDFLAGS="$(LDFLAGS)"

all: $(VER)/Makefile
	$(_MAKE) -C $(VER)/pppd
ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
	$(_MAKE) -C $(VER)/pppd/plugins
endif
ifeq ($(CONFIG_USER_CHAT_CHAT),y)
	$(_MAKE) -C $(VER)/chat
endif

$(VER)/Makefile:
	cd $(VER) ; \
	./configure --prefix=/usr --sysconfdir=/etc/ppp
	cp $(VER)/pppd/Makefile $(VER)/pppd/Makefile.sed
	sed \
		-e 's:ifdef PLUGIN:ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y):' \
		-e 's:ifdef HAS_SHADOW:ifeq (1,0):' \
		-e 's:ifdef FILTER:ifneq ($(CONFIG_LIB_LIBPCAP)$(CONFIG_LIB_LIBPCAP_FORCE),):' \
		-e 's:ifdef USE_PAM:ifeq ($(CONFIG_USER_PPPD_WITH_PAM),y):' \
		-e 's:ifdef MPPE:ifeq ($(CONFIG_USER_PPPD_WITH_MPPE),y):' \
		$(VER)/pppd/Makefile.sed > $(VER)/pppd/Makefile
	rm -f $(VER)/pppd/Makefile.sed

romfs:
	$(ROMFSINST) -d -e CONFIG_USER_CHAT_CHAT $(VER)/chat/chat /usr/sbin/chat
	$(ROMFSINST) -d -e CONFIG_USER_PPPD_PPPD_PPPD $(VER)/pppd/pppd /usr/sbin/pppd
	$(ROMFSINST) -d -e CONFIG_USER_PPPD_PPPD_PPPD $(VER)/etc.ppp /etc/ppp
ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
	set -e ; \
	for f in `find $(VER)/pppd/plugins -name '*.so'` ; do \
		$(ROMFSINST) -d $$f /usr/lib/pppd/$(patsubst ppp-%,%,$(VER))/`basename $$f` ; \
	done
endif

clean:
	rm -f $(VER)/pppd/Makefile.sed $(VER)/pppd/pppd.gdb
	[ ! -e $(VER)/Makefile ] || $(MAKE) -C $(VER) dist-clean

.PHONY: all clean romfs
