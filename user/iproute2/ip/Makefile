IPOBJ=ip.o ipaddress.o iproute.o iprule.o \
    rtm_map.o iptunnel.o ipneigh.o iplink.o ipmaddr.o \
    ipmonitor.o ipmroute.o

RTMONOBJ=rtmon.o

RTACCTOBJ=rtacct.o

ALLOBJ=$(IPOBJ) $(ADDOBJ) $(RTOBJ)

all: ip rtmon rtacct

ip: $(IPOBJ) $(LIBNETLINK) $(LIBUTIL)

rtmon: $(RTMONOBJ) $(LIBNETLINK)

rtacct: $(RTACCTOBJ)

romfs:
	$(ROMFSINST) -e CONFIG_USER_IPROUTE2_IP_IFCFG  /bin/ifcfg
	$(ROMFSINST) -e CONFIG_USER_IPROUTE2_IP_IP     /bin/ip
	$(ROMFSINST) -e CONFIG_USER_IPROUTE2_IP_ROUTEF /bin/routef
	$(ROMFSINST) -e CONFIG_USER_IPROUTE2_IP_ROUTEL /bin/routel
	$(ROMFSINST) -e CONFIG_USER_IPROUTE2_IP_RTACCT /bin/rtacct
	$(ROMFSINST) -e CONFIG_USER_IPROUTE2_IP_RTMON  /bin/rtmon
	$(ROMFSINST) -e CONFIG_USER_IPROUTE2_IP_RTPR   /bin/rtpr

clean:
	rm -f $(IPOBJ) $(RTMONOBJ) $(RTACCTOBJ) ip rtmon rtacct *.gdb
