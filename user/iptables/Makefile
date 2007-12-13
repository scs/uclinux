VER = iptables-1.3.6

all:
	$(MAKE) -C $(VER)

clean:
	$(MAKE) -C $(VER) clean
	rm -rf DESTDIR-$(VER)

romfs:
	$(ROMFSINST) $(VER)/iptables /bin/iptables
	$(ROMFSINST) -e CONFIG_USER_IPTABLES_IP6TABLES $(VER)/ip6tables /bin/ip6tables
	$(ROMFSINST) -l iptables /bin/iptables-save
	$(ROMFSINST) -l iptables /bin/iptables-restore

.PHONY: all clean romfs
