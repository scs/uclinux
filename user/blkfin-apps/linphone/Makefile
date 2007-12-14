linphone_subdirs = libosip2-3.0.3-2
linphone_subdirs += libeXosip2-3.0.3-3
linphone_subdirs += linphone-2.0.0
export TEMPDIR=$(CURDIR)/temp

all:
	for i in $(linphone_subdirs) ; do $(MAKE) -C $$i -f ucldist.mk $@ || exit $$? ; done

romfs:
	$(ROMFSINST) $(TEMPDIR)/usr/bin/linphonec /bin/linphonec
	mkdir -p $(ROMFSDIR)/usr/share/sounds/linphone/rings
	$(ROMFSINST) $(TEMPDIR)/usr/share/sounds/linphone/ringback.wav /usr/share/sounds/linphone/ringback.wav
	$(ROMFSINST) $(TEMPDIR)/usr/share/sounds/linphone/rings/oldphone.wav /usr/share/sounds/linphone/rings/oldphone.wav

clean:
	rm -Rf $(TEMPDIR)
	for i in $(linphone_subdirs) ; do $(MAKE) -C $$i -f ucldist.mk $@ || exit $$? ; done

.PHONY: all clean romfs
