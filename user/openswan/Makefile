
CFLAGS := $(subst -Werror,,$(CFLAGS))

.EXPORT_ALL_VARIABLES:

FINALLIBEXECDIR="/bin"
ifdef CONFIG_USER_FLATFSD_FLATFSD
FINALCONFDIR        := "/etc/config"
FINALCONFDDIR       := "/etc/config"
USE_SINGLE_CONF_DIR := true
USE_WEAKSTUFF       := true
HAVE_DYNAMICDNS     := true
USE_DEFAULT_CONNS   := "no"
endif
FINALSBINDIR="/bin"
FINALLIBDIR="/bin"
OPENSWAN_DIR = $(ROOTDIR)/openswan

programs:  dummy_target
	if [ -d $(OPENSWAN_DIR) ]; then \
		ROOTDIR="$(ROOTDIR)" LDFLAGS="$(LDFLAGS)" LDLIBS="$(LDLIBS)" $(MAKE) -C $(OPENSWAN_DIR) $@ ; \
	fi

clean:  dummy_target
	if [ -d $(OPENSWAN_DIR) ]; then \
		ROOTDIR="$(ROOTDIR)" CFLAGS="$(CFLAGS)" LDLIBS="$(LDLIBS)" $(MAKE) -C $(OPENSWAN_DIR) $@ ; \
	fi

romfs:
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_PLUTO_PLUTO $(OPENSWAN_DIR)/programs/pluto/pluto /bin/pluto
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_PLUTO_PLUTO $(OPENSWAN_DIR)/programs/pluto/_pluto_adns /bin/_pluto_adns
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_PLUTO_WHACK $(OPENSWAN_DIR)/programs/pluto/whack /bin/whack
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_UTILS_RANBITS $(OPENSWAN_DIR)/programs/ranbits/ranbits /bin/ranbits
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_UTILS_RSASIGKEY $(OPENSWAN_DIR)/programs/rsasigkey/rsasigkey /bin/rsasigkey
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_KLIPS_EROUTE $(OPENSWAN_DIR)/programs/eroute/eroute /bin/eroute
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_KLIPS_KLIPSDEBUG $(OPENSWAN_DIR)/programs/klipsdebug/klipsdebug /bin/klipsdebug
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_KLIPS_SPI $(OPENSWAN_DIR)/programs/spi/spi /bin/spi
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_KLIPS_SPIGRP $(OPENSWAN_DIR)/programs/spigrp/spigrp /bin/spigrp
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_KLIPS_TNCFG $(OPENSWAN_DIR)/programs/tncfg/tncfg /bin/tncfg
ifndef CONFIG_USER_IPSEC_CONFIGURATOR
ifndef CONFIG_PROP_IFMOND_IPSEC
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/_confread/_confread /bin/_confread
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/look/look /bin/look
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/secrets/secrets /bin/secrets
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/showhostkey/showhostkey /bin/showhostkey
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/_updown/_updown /bin/_updown
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/auto/auto /bin/auto
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/_copyright/_copyright /bin/_copyright
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/_keycensor/_keycensor /bin/_keycensor
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/manual/manual /bin/manual
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/_plutoload/_plutoload /bin/_plutoload
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/_realsetup/_realsetup /bin/_realsetup
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/send-pr/send-pr /bin/send-pr
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/_updown_x509/_updown_x509 /bin/_updown_x509
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/barf/barf /bin/barf
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/ikeping/ikeping /bin/ikeping
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/newhostkey/newhostkey /bin/newhostkey
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/_plutorun/_plutorun /bin/_plutorun
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/_startklips/_startklips /bin/_startklips
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/verify/verify /bin/verify
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/calcgoo/calcgoo /bin/calcgoo
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/_include/_include /bin/_include
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/livetest/livetest /bin/livetest
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/pf_key/pf_key /bin/pf_key
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/_secretcensor/_secretcensor /bin/_secretcensor
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/showdefaults/showdefaults /bin/showdefaults
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/ipsec/ipsec /bin/ipsec
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OPENSWAN_DIR)/programs/setup/setup /bin/setup
endif
endif

dummy_target:
