VER = links-2.2

CONF_OPTS = \
	$(call USE_ENABLE,LIB_LIBPNG,graphics) \
	--without-svgalib \
	--without-x \
	--with-fb \
	$(call USE_WITH,LIB_DIRECTFB,directfb) \
	--without-gpm \
	$(call USE_WITH,LIB_LIBJPEG,libjpeg) \
	$(call USE_WITH,LIB_LIBTIFF,libtiff) \
	$(call USE_WITH,LIB_LIBSSL,ssl) \
	$(call USE_WITH,LIB_ZLIB,zlib) \
	$(call USE_WITH,LIB_LIBBZ2,bzip2)

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/links /usr/bin/links
