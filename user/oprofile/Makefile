#VER = oprofile-0.9.2.1rc1
VER = oprofile-0.9.1
CONF_OPTS= --with-kernel-support
FILE_IMAGE = $(ROOTDIR)/$(LINUXDIR)/vmlinux

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/oprofiled /usr/bin/oprofiled
	$(ROMFSINST)    $(STAGEDIR)/usr/bin/opreport /usr/bin/opreport
	$(ROMFSINST)    $(STAGEDIR)/usr/bin/opannotate /usr/bin/opannotate
	$(ROMFSINST)    $(STAGEDIR)/usr/bin/oparchive /usr/bin/oparchive
	$(ROMFSINST)    $(STAGEDIR)/usr/bin/opgprof /usr/bin/opgprof
	$(ROMFSINST)    $(STAGEDIR)/usr/bin/ophelp /usr/bin/ophelp
	$(ROMFSINST)    $(STAGEDIR)/usr/bin/opcontrol /usr/bin/opcontrol
	$(ROMFSINST)    $(STAGEDIR)/usr/bin/opreport /usr/bin/opreport
	#$(ROMFSINST) -d $(STAGEDIR)/usr/share/oprofile/arm/xscale2/events /usr/share/oprofile/arm/xscale2/events
	#$(ROMFSINST) -d $(STAGEDIR)/usr/share/oprofile/arm/xscale2/unit_masks /usr/share/oprofile/arm/xscale2/unit_masks
	$(ROMFSINST) -S $(FILE_IMAGE) /vmlinux
	range_info=`objdump -h $(FILE_IMAGE) 2>/dev/null | grep " .text "`; \
	tmp1=`echo $$range_info | awk '{print $$4}'`; \
	tmp_length=`echo $$range_info | awk  '{print $$3}'`; \
	tmp2=`objdump -h $(FILE_IMAGE) --adjust-vma=0x$$tmp_length 2>/dev/null | grep " .text " | awk  '{print $$4}'`; \
	sed "/--vmlinux=/s:kernel-range=.* :kernel-range=$$tmp1,$$tmp2 :" bfin_opcontrol > build-$(VER)/bfin_opcontrol; \
	chmod a+x build-$(VER)/bfin_opcontrol; \
	$(ROMFSINST)    build-$(VER)/bfin_opcontrol /usr/bin/bfin_opcontrol; \
	$(ROMFSINST) -a "if [ -e /proc/sys/kernel/hung_task_timeout_secs ]; then echo 0 > /proc/sys/kernel/hung_task_timeout_secs; fi" /etc/rc
