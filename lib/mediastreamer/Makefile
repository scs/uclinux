VER = mediastreamer-2.1.0

CONF_OPTS = \
	--disable-strict \
	SPEEX_LIBS="-L$(STAGEDIR)/usr/lib -lspeex -lspeexdsp -lm" \
	$(call USE_ENABLE,LIB_FFMPEG,video)

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/libexec/mediastream /usr/libexec/mediastream
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libmediastreamer.so.0 /usr/lib/libmediastreamer.so.0
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libquickstream.so.0 /usr/lib/libquickstream.so.0
