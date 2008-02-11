VER = ortp-0.13.1

# disable generation of documentation
export ac_cv_path_DOXYGEN = false

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libortp.so.5 /usr/lib/libortp.so.5
