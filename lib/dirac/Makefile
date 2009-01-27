VER = dirac-1.0.0
URL = http://downloads.sourceforge.net/sourceforge/dirac/$(VER).tar.gz

export ac_cv_prog_HAVE_DOXYGEN = false
export ac_cv_prog_HAVE_LATEX = false

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libdirac_decoder.so.0 /usr/lib/libdirac_decoder.so.0
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libdirac_encoder.so.0 /usr/lib/libdirac_encoder.so.0
