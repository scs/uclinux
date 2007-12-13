VER = iptables-1.3.8

IPTABLES_OPTS = \
	DO_MULTI=1 \
	KERNEL_DIR=$(ROOTDIR)/$(LINUXDIR) \
	COPT_FLAGS="${CFLAGS}" \
	LIBDIR=/usr/lib

ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),)
IPTABLES_OPTS += NO_SHARED_LIBS=1
endif

ifeq ($(CONFIG_USER_IPTABLES_IP6TABLES),y)
IPTABLES_OPTS += DO_IPV6=1
else
IPTABLES_OPTS += DO_IPV6=0
endif

all:
	$(MAKE) -C $(VER) $(IPTABLES_OPTS)

clean:
	$(MAKE) -C $(VER) clean

romfs:
	$(ROMFSINST) $(VER)/iptables /bin/iptables
	$(ROMFSINST) -e CONFIG_USER_IPTABLES_IP6TABLES $(VER)/ip6tables /bin/ip6tables
	$(ROMFSINST) -l /bin/iptables /bin/iptables-save
	$(ROMFSINST) -l /bin/iptables /bin/iptables-restore

ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
	set -e; \
	for f in $(VER)/extensions/*.so ; do \
		f=$${f##*/}; \
		$(ROMFSINST) -d $(VER)/extensions/$$f /usr/lib/iptables/$$f; \
	done
endif

.PHONY: all clean romfs
