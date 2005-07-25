
ifdef CONFIG_USER_MYSQL_CLIB
CFLAGS += -I$(ROOTDIR)/user/mysql/include -DENABLE_MYSQL
LDLIBS := -L$(ROOTDIR)/user/mysql/libmysql/.libs -lmysqlclient $(LDLIBS)
endif

all: build/Makefile
	$(MAKE) -C build

build/Makefile: makefile
	chmod u+x configure
	rm -rf build
	mkdir build
	( \
		cd build; \
		CC="$(CC) -I$(ROOTDIR)/user/snort/build $(CFLAGS)" \
		LDFLAGS="-L$(ROOTDIR)/lib/Libnet/lib $(LDFLAGS)" \
		LIBS="$(LDLIBS)" \
		PATH="$(PATH):$(ROOTDIR)/lib/Libnet" \
			../configure --host=$(CROSS_COMPILE:-=) \
			--enable-dependency-tracking \
			--enable-inline \
			--with-libipq-includes=$(ROOTDIR)/user/iptables/include/libipq \
			--with-libipq-libraries=$(ROOTDIR)/user/iptables/libipq \
			--with-libnet-includes=$(ROOTDIR)/lib/Libnet/include \
			--with-libnet-libraries=$(ROOTDIR)/lib/Libnet/lib \
			; \
	)

romfs:
	$(ROMFSINST) build/src/snort /bin/snort
	$(ROMFSINST) -s /bin/snort /bin/snort-inline
	$(ROMFSINST) rules/local.rules /etc/default/local.rules
	$(ROMFSINST) drop-rules/local.rules /etc/default/local-drop.rules
	# Copy default rule set across
	[ -d $(ROMFSDIR)/etc/snort ] || mkdir $(ROMFSDIR)/etc/snort
	[ -d $(ROMFSDIR)/etc/snort/drop-rules ] || mkdir $(ROMFSDIR)/etc/snort/drop-rules
	for i in rules/*.rules; do $(ROMFSINST) $$i /etc/snort/`basename $$i`; done
	for i in drop-rules/*.rules; do $(ROMFSINST) $$i /etc/snort/drop-rules/`basename $$i`; done
	# Local rules go elsewhere...
	if [ -f $(ROMFSDIR)/etc/snort/local.rules ]; then rm -f $(ROMFSDIR)/etc/snort/local.rules; fi
	if [ -f $(ROMFSDIR)/etc/snort/drop-rules/local.rules ]; then rm -f $(ROMFSDIR)/etc/snort/drop-rules/local.rules; fi
	$(ROMFSINST) etc/classification.config /etc/snort/classification.config
	$(ROMFSINST) etc/reference.config /etc/snort/reference.config
	$(ROMFSINST) etc/unicode.map /etc/snort/unicode.map

clean:
	rm -rf build

