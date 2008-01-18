OBJS = cache.o rfc1035.o util.o option.o forward.o network.o \
       dnsmasq.o netlink.o isc.o dhcp.o lease.o helper.o rfc2131.o preload.o

BINDIR = /usr/local/sbin
MANDIR = /usr/local/man

CFLAGS += -DNO_GETTEXT -DHAVE_ISC_READER -DDO_PRELOAD

CFLAGS += -g -O2
ifndef CONFIG_IPV6
CFLAGS += -DNO_IPV6
endif
ifdef CONFIG_USER_FLATFSD_FLATFSD
CFLAGS += -DETC_DIR=\"/etc/config\"
endif

all : dnsmasq

clean :
	rm -f *~ $(OBJS) dnsmasq dnsmasq.gdb

.c.o: dnsmasq.h config.h
	$(CC) -Wall -c $(CFLAGS) $*.c

dnsmasq : $(OBJS) dnsmasq.h config.h
	$(CC) $(LDFLAGS) -o $@  $(OBJS) $(LDLIBS$(LDLIBS_$@))

install : dnsmasq
	install -d $(BINDIR) -d $(MANDIR)
	install -m 644 dnsmasq.8 $(MANDIR)/man8
	install -m 755 dnsmasq $(BINDIR)

romfs:
	$(ROMFSINST) /bin/dnsmasq
