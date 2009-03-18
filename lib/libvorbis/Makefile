VER = libvorbis-1.2.0

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libvorbisenc.so.2 /usr/lib/libvorbisenc.so.2
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libvorbisfile.so.3 /usr/lib/libvorbisfile.so.3
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libvorbis.so.0 /usr/lib/libvorbis.so.0
