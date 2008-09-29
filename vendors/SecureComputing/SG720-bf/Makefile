#
#	Makefile -- Build instructions for SecureComputing SG720
#

ROMFSIMG  = $(IMAGEDIR)/ramdisk
ZIMAGE    = $(IMAGEDIR)/zImage
IMAGE     = $(IMAGEDIR)/image.bin
#MBRIMG    = $(IMAGEDIR)/mbr.img

BOOTROMFS = $(ROOTDIR)/romfs2
BOOTRAMDISK= $(IMAGEDIR)/bootramdisk

SQUASH_ENDIAN = -be

ROMFS_DIRS = $(DEFAULT_ROMFS_DIRS) boot oldroot

DEVICES += $(DEVICE_PTY_64)

FLASH_DEVICES = \
	boot,c,90,0 \
	tags,c,90,2 \
	log,c,90,4 \
	image,b,3,0 \
	config,b,3,2

all:

clean: image.clean

romfs: romfs_dev romfs.dirs romfs.symlinks romfs.default romfs.rc romfs.version romfs.boot romfs.cryptokey
	$(ROMFSINST) ../network.init.std /etc/network.init
	$(ROMFSINST) ../firewall.init.std /etc/firewall.init
	$(ROMFSINST) -e CONFIG_USER_LM_SENSORS_SENSORS sensors.conf /etc/sensors.conf

romfs.post:: romfs.no-ixp400-modules romfs.ixp425-microcode

image: image.configs image.dir image.arm.zimage image.squashfs7z image.mbr image.bin image.tag image.copy
	rm -rf $(BOOTROMFS)
	cp -r $(ROMFSDIR) $(BOOTROMFS)
	for FILE in acld authd auth-down auth-up avscan awk bgpd bpalogin br brctl chat clamboot clamd clamfilter clamsmtpd conntrack cpu create-siproxd-conf.tcl cron dhcpcd dhcpd dhcrelay diald discard dnsmasq enableweb eroute ethtool ez-ipupdate firewall firewallenv flash flashkey flashw flatfsd freshclam frox gen-keys gen-ssl-cert gettyd gratuitous_arp gre highavaild hping htc hts httpd https-certgen hwclock idb ifhasip ifmond ifready ifretry if_status inetd inetd-echo initconf initdhcpd ip ip6tables ipsec ipset iptables iptables-restore iptables-save kill klipsdebug l2tpd logd login lspci mail metash mount-squid mtuchk nasl nc netflash netstat nflogd nmap ntpd ntpdate ntpq openssl openvpn ospfd pam_tally passwd pcidssd ping ping6 pluto _pluto_adns pop3.proxy portmap pppd pppoe-up pptp pptpctrl pptpd preload_notify proxy80 queryacld radauth radvd radvdump ranbits redialer ripd routef routel rrdtool rsasigkey rtacct rtmon saveall scp setmac setpci sgadnsd sgsnmpd showconfig shtcl siproxd smbmnt smbmount smbumount snmpd snort snort-inline snort-starter spi spigrp squid squidclient ssh sshd ssh-keygen sslwrap statsd strace stunnel sysctl tc tcpblast tcpdump telnetd test-nasl tip tload tncfg tracepath6 traceroute traceroute6 ts2-query ts-query tune2fs upnpd usleep vconfig vmstat vpn-down vpn-up whack zcat zebra ; do \
		rm -f $(BOOTROMFS)/bin/$$FILE ; \
	done
	for FILE in arp etherwake ifconfig mii-tool route ; do \
		rm -f $(BOOTROMFS)/sbin/$$FILE ; \
	done
	rm -rf $(BOOTROMFS)/etc/*
	rm -rf $(BOOTROMFS)/home
	rm -rf $(BOOTROMFS)/boot
	rm -rf $(BOOTROMFS)/usr/share
	rm -rf $(BOOTROMFS)/lib/tcl
	rm -rf $(BOOTROMFS)/lib/security
	rm -rf $(BOOTROMFS)/lib/modules
	rm -rf $(BOOTROMFS)/lib/ipset
	rm -rf $(BOOTROMFS)/lib/libnet*
	rm -f $(BOOTROMFS)/lib/libnessus*
	rm -f $(BOOTROMFS)/lib/libclam*
	rm -f $(BOOTROMFS)/lib/libupnp*
	rm -f $(BOOTROMFS)/lib/libstatsd*
	rm -f $(BOOTROMFS)/lib/libssl*
	rm -f $(BOOTROMFS)/tmp
	rm -f $(BOOTROMFS)/mnt
	rm -rf $(BOOTROMFS)/var
	mkdir $(BOOTROMFS)/mnt1
	mkdir $(BOOTROMFS)/mnt2
	cp rc.boot $(BOOTROMFS)/etc/rc
	rm -f $(BOOTRAMDISK); mksquashfs7z=`pwd`/mksquashfs7z; cd $(BOOTROMFS);\
        $$mksquashfs7z . $(BOOTRAMDISK) -all-root -noappend $(SQUASH_ENDIAN)
	cat $(BOOTRAMDISK) $(ZIMAGE) > $(IMAGEDIR)/image.boot.bin

.PHONY: image.mbr

image.mbr: $(MBRIMG)

$(MBRIMG):
	$(DD) if=/dev/zero of=$@ bs=512 count=1
	printf "1,48575,L,*\n,,61,-\n" | /sbin/sfdisk  -uS -C 966 -H 16 -S 4 $@

include $(ROOTDIR)/vendors/config/config.dev
include ../vendor.mak
