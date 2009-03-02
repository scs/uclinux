VER = iperf-2.0.4

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -e CONFIG_USER_IPERF_IPERF build-$(VER)/src/iperf /bin/iperf
