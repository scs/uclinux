VER = curl-7.19.2

CONF_OPTS = --with-random=/dev/urandom

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libcurl.so.5 /usr/lib/libcurl.so.5
	$(ROMFSINST) -d -e CONFIG_USER_CURL_CURL $(STAGEDIR)/usr/bin/curl /usr/bin/curl
