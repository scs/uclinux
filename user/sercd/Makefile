VER = sercd-3.0.0

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/sbin/sercd /usr/sbin/sercd
	$(ROMFSINST) -e CONFIG_USER_SERCD \
		-a "sredir stream tcp nowait root /bin/sercd 8 /dev/rfc2217 /var/lock/LCK..rfc2217" /etc/inetd.conf
	$(ROMFSINST) -e CONFIG_USER_SERCD -a "sredir 7051/tcp" /etc/services
