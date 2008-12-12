VER = libosip2-3.2.0

include $(ROOTDIR)/tools/autotools.mk

# the osip libs are simple, so no need for the libtool linker scripts.  they
# can just get in the way due to their interdependencies.
post-build::
	rm -f $(STAGEDIR)/usr/lib/libosip2.la $(STAGEDIR)/usr/lib/libosipparser2.la

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libosip2.so.3 /usr/lib/libosip2.so.3
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libosipparser2.so.3 /usr/lib/libosipparser2.so.3
