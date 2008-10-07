VER = mpd-0.13.2

CONF_OPTS = \
	$(call USE_ENABLE,LIB_LIBAO,ao) \
	--disable-shout \
	--disable-iconv \
	--disable-ipv6 \
	$(call USE_ENABLE,LIB_ALSA_LIB,alsa) \
	--disable-jack \
	--disable-pulse \
	--disable-oggvorbis \
	--disable-oggflac \
	$(call USE_ENABLE,LIB_FLAC,flac=$(STAGEDIR)) \
	$(call USE_ENABLE,LIB_LIBMAD,mp3) \
	$(call USE_ENABLE,LIB_FAAD2,aac) \
	--disable-audiofile \
	--disable-mod \
	$(call USE_ENABLE,LIB_LIBID3TAG,id3) \
	--disable-lsr

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/mpd /usr/bin/mpd
	$(ROMFSINST) /etc/mpd.conf
