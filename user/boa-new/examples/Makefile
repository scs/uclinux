
all:

romfs:
	mkdir -p $(ROMFSDIR)/home/www
	mkdir -p $(ROMFSDIR)/etc/boa-test
	$(ROMFSINST) -e CONFIG_USER_BOA_NEW_TEST /etc/boa-test/boa.conf
	$(ROMFSINST) -e CONFIG_USER_BOA_NEW_TEST /home/www
