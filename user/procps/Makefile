VER = procps-3.2.7

CPPFLAGS += -I$(STAGEDIR)/usr/include/ncurses

ifeq ($(CONFIGURE_SHARED_ENABLE),--enable-shared)
export SHARED = 1
else
export SHARED = 0
endif

ALL-y :=
ALL-$(CONFIG_USER_PROCPS_KILL)   += kill
ALL-$(CONFIG_USER_PROCPS_UPTIME) += uptime
ALL-$(CONFIG_USER_PROCPS_TLOAD)  += tload
ALL-$(CONFIG_USER_PROCPS_FREE)   += free
ALL-$(CONFIG_USER_PROCPS_W)      += w
ALL-$(CONFIG_USER_PROCPS_TOP)    += top
ALL-$(CONFIG_USER_PROCPS_VMSTAT) += vmstat
ALL-$(CONFIG_USER_PROCPS_WATCH)  += watch
ALL-$(CONFIG_USER_PROCPS_SKILL)  += skill
ALL-$(CONFIG_USER_PROCPS_SNICE)  += snice
ALL-$(CONFIG_USER_PROCPS_PGREP)  += pgrep
ALL-$(CONFIG_USER_PROCPS_PKILL)  += pkill
ALL-$(CONFIG_USER_PROCPS_SYSCTL) += sysctl

all:
	$(MAKE) \
		CFLAGS="$(CFLAGS)" \
		CPPFLAGS="$(CPPFLAGS)" \
		LDFLAGS="$(LDFLAGS)" \
		ALL="$(ALL-y)" \
		SHARED=$(SHARED) \
		lib64=lib \
		-C $(VER)

clean:
	$(MAKE) -C $(VER) clean

romfs:
ifeq ($(SHARED),1)
	lib=`basename $(wildcard $(VER)/proc/libproc-*.so)` ; \
	$(ROMFSINST) $(VER)/proc/$$lib /lib/$$lib
endif
	$(ROMFSINST) -d -e CONFIG_USER_PROCPS_FREE $(VER)/free /usr/bin/free
	$(ROMFSINST) -d -e CONFIG_USER_PROCPS_KILL $(VER)/kill /bin/kill
	$(ROMFSINST) -d -e CONFIG_USER_PROCPS_PGREP $(VER)/pgrep /usr/bin/pgrep
	$(ROMFSINST) -d -e CONFIG_USER_PROCPS_PKILL $(VER)/pkill /usr/bin/pkill
	$(ROMFSINST) -d -e CONFIG_USER_PROCPS_PS $(VER)/ps /usr/bin/ps
	$(ROMFSINST) -d -e CONFIG_USER_PROCPS_SKILL $(VER)/skill /usr/bin/skill
	$(ROMFSINST) -d -e CONFIG_USER_PROCPS_SNICE $(VER)/snice /usr/bin/snice
	$(ROMFSINST) -d -e CONFIG_USER_PROCPS_SYSCTL $(VER)/sysctl /usr/bin/sysctl
	$(ROMFSINST) -d -e CONFIG_USER_PROCPS_TLOAD $(VER)/tload /usr/bin/tload
	$(ROMFSINST) -d -e CONFIG_USER_PROCPS_TOP $(VER)/top /usr/bin/top
	$(ROMFSINST) -d -e CONFIG_USER_PROCPS_UPTIME $(VER)/uptime /usr/bin/uptime
	$(ROMFSINST) -d -e CONFIG_USER_PROCPS_VMSTAT $(VER)/vmstat /usr/bin/vmstat
	$(ROMFSINST) -d -e CONFIG_USER_PROCPS_W $(VER)/w /usr/bin/w
	$(ROMFSINST) -d -e CONFIG_USER_PROCPS_WATCH $(VER)/watch /usr/bin/watch

.PHONY: all clean romfs
