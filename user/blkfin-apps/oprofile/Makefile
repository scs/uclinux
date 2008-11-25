VER = oprofile-0.9.4
CONF_OPTS= --with-kernel-support

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/oprofiled /usr/bin/oprofiled
	$(ROMFSINST)    $(STAGEDIR)/usr/bin/opreport /usr/bin/opreport
	$(ROMFSINST)    $(STAGEDIR)/usr/bin/opannotate /usr/bin/opannotate
	$(ROMFSINST)    $(STAGEDIR)/usr/bin/oparchive /usr/bin/oparchive
	$(ROMFSINST)    $(STAGEDIR)/usr/bin/opgprof /usr/bin/opgprof
	$(ROMFSINST)    $(STAGEDIR)/usr/bin/ophelp /usr/bin/ophelp
	$(ROMFSINST)    $(STAGEDIR)/usr/bin/opcontrol /usr/bin/opcontrol
	$(ROMFSINST)    bfin_opcontrol /usr/bin/bfin_opcontrol
	$(ROMFSINST) -d $(STAGEDIR)/usr/share/oprofile /usr/share/oprofile
