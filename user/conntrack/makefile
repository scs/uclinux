CONFOPTS = --prefix=

all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) build/src/conntrack /bin/conntrack
	$(ROMFSINST) -d build/extensions/.libs/ct_proto_tcp.so /lib/conntrack/ct_proto_tcp.so
	$(ROMFSINST) build/extensions/.libs/ct_proto_udp.so /lib/conntrack/ct_proto_udp.so
	$(ROMFSINST) build/extensions/.libs/ct_proto_icmp.so /lib/conntrack/ct_proto_icmp.so
	$(ROMFSINST) -e CONFIG_IP_NF_CT_PROTO_SCTP build/extensions/.libs/ct_proto_sctp.so /lib/conntrack/ct_proto_sctp.so
