linphone_subdirs = libosip2
linphone_subdirs += linphone
export TEMPDIR=$(CURDIR)/temp


all:
	for i in $(linphone_subdirs) ; do  make -C $$i -f ucldist.mk  || exit $? ; done

romfs:
	$(ROMFSINST) $(TEMPDIR)/usr/bin/linphonec /bin/linphonec
	mkdir -p $(ROMFSDIR)/usr/share/sounds/linphone/rings
	$(ROMFSINST) $(TEMPDIR)/usr/share/sounds/linphone/ringback.wav /usr/share/sounds/linphone/ringback.wav
	$(ROMFSINST) $(TEMPDIR)/usr/share/sounds/linphone/rings/oldphone.wav /usr/share/sounds/linphone/rings/oldphone.wav

clean:
	rm -Rf $(TEMPDIR)
	-for i in $(linphone_subdirs) ; do \
                [ ! -d $$i ] || make -C $$i -f ucldist.mk clean; \
	done

