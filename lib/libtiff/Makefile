VER = tiff-4.0.0beta3

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libtiff.so.5.0.0 /lib/
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libtiffxx.so.5.0.0 /lib/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiffcp /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/fax2ps /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/ppm2tiff /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/raw2tiff /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiff2rgba /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/fax2tiff /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/bmp2tiff /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiffdither /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiffcrop /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/pal2rgb /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiffmedian /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/ras2tiff /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/rgb2ycbcr /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/thumbnail /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiffset /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiffcmp /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiffdump /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiff2bw /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiff2ps /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiffsplit /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiffinfo /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/gif2tiff /usr/bin/
	$(ROMFSINST) -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiff2pdf /usr/bin/
