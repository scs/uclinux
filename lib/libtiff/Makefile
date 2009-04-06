VER = tiff-4.0.0beta3

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libtiff.so.5 /usr/lib/
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libtiffxx.so.5 /usr/lib/

	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiffcp /usr/bin/tiffcp
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/fax2ps /usr/bin/fax2ps
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/ppm2tiff /usr/bin/ppm2tiff
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/raw2tiff /usr/bin/raw2tiff
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiff2rgba /usr/bin/tiff2rgba
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/fax2tiff /usr/bin/fax2tiff
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/bmp2tiff /usr/bin/bmp2tiff
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiffdither /usr/bin/tiffdither
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiffcrop /usr/bin/tiffcrop
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/pal2rgb /usr/bin/pal2rgb
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiffmedian /usr/bin/tiffmedian
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/ras2tiff /usr/bin/ras2tiff
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/rgb2ycbcr /usr/bin/rgb2ycbcr
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/thumbnail /usr/bin/thumbnail
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiffset /usr/bin/tiffset
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiffcmp /usr/bin/tiffcmp
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiffdump /usr/bin/tiffdump
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiff2bw /usr/bin/tiff2bw
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiff2ps /usr/bin/tiff2ps
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiffsplit /usr/bin/tiffsplit
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiffinfo /usr/bin/tiffinfo
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/gif2tiff /usr/bin/gif2tiff
	$(ROMFSINST) -d -e CONFIG_LIB_TIFF_EXAMPLES $(STAGEDIR)/usr/bin/tiff2pdf /usr/bin/tiff2pdf
