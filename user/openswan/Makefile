
CFLAGS := $(subst -Werror,,$(CFLAGS))

.EXPORT_ALL_VARIABLES:

FINALLIBEXECDIR="/bin"
FINALCONFDIR="/etc/config"
FINALCONFDDIR="/etc/config"
FINALSBINDIR="/bin"
FINALLIBDIR="/bin"

programs:  dummy_target
	ROOTDIR="$(ROOTDIR)" LDFLAGS="$(LDFLAGS)" LDLIBS="$(LDLIBS)" $(MAKE) programs -C $(ROOTDIR)/openswan $@

clean:  dummy_target
	ROOTDIR="$(ROOTDIR)" CFLAGS="$(CFLAGS)" LDLIBS="$(LDLIBS)" $(MAKE) clean -C $(ROOTDIR)/openswan $@

romfs:
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_PLUTO_PLUTO $(ROOTDIR)/openswan/programs/pluto/pluto /bin/pluto
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_PLUTO_PLUTO $(ROOTDIR)/openswan/programs/pluto/_pluto_adns /bin/_pluto_adns
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_PLUTO_WHACK $(ROOTDIR)/openswan/programs/pluto/whack /bin/whack
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_UTILS_RANBITS $(ROOTDIR)/openswan/programs/ranbits/ranbits /bin/ranbits
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_UTILS_RSASIGKEY $(ROOTDIR)/openswan/programs/rsasigkey/rsasigkey /bin/rsasigkey
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_KLIPS_EROUTE $(ROOTDIR)/openswan/programs/eroute/eroute /bin/eroute
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_KLIPS_KLIPSDEBUG $(ROOTDIR)/openswan/programs/klipsdebug/klipsdebug /bin/klipsdebug
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_KLIPS_SPI $(ROOTDIR)/openswan/programs/spi/spi /bin/spi
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_KLIPS_SPIGRP $(ROOTDIR)/openswan/programs/spigrp/spigrp /bin/spigrp
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_KLIPS_TNCFG $(ROOTDIR)/openswan/programs/tncfg/tncfg /bin/tncfg
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/_confread/_confread /bin/_confread
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/look/look /bin/look
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/secrets/secrets /bin/secrets
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/showhostkey/showhostkey /bin/showhostkey
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/_updown/_updown /bin/_updown
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/auto/auto /bin/auto
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/_copyright/_copyright /bin/_copyright
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/_keycensor/_keycensor /bin/_keycensor
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/manual/manual /bin/manual
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/_plutoload/_plutoload /bin/_plutoload
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/_realsetup/_realsetup /bin/_realsetup
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/send-pr/send-pr /bin/send-pr
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/_updown_x509/_updown_x509 /bin/_updown_x509
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/barf/barf /bin/barf
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/ikeping/ikeping /bin/ikeping
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/newhostkey/newhostkey /bin/newhostkey
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/_plutorun/_plutorun /bin/_plutorun
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/_startklips/_startklips /bin/_startklips
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/verify/verify /bin/verify
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/calcgoo/calcgoo /bin/calcgoo
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/_include/_include /bin/_include
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/livetest/livetest /bin/livetest
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/pf_key/pf_key /bin/pf_key
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/_secretcensor/_secretcensor /bin/_secretcensor
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/showdefaults/showdefaults /bin/showdefaults
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/ipsec/ipsec /bin/ipsec
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN $(ROOTDIR)/openswan/programs/setup/setup /bin/setup

dummy_target:
