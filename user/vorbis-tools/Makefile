VER = vorbis-tools-1.2.0

# If curl is actually enabled, it will be found via pkg-config in spite of
# the configure flag below "--without-curl" ...
CONF_OPTS := \
	--with-ao=$(STAGEDIR)/usr/lib/libao.so \
	--with-ao-libraries=$(STAGEDIR)/usr/lib/ \
	--with-ao-includes=$(STAGEDIR)/usr/include/ \
	--disable-nls \
	--without-curl

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/ogg123 /usr/bin/ogg123
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/oggdec /usr/bin/oggdec
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/oggenc /usr/bin/oggenc
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/ogginfo /usr/bin/ogginfo
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/vorbiscomment /usr/bin/vorbiscomment
