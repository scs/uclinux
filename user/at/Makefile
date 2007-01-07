LDFLAGS += -L$(ROOTDIR)/lib/flex/build

CONFIGURE_OPTS += --with-jobdir=/var/spool/cron/atjobs --with-atspool=/var/spool/cron/atspool

all: build/Makefile
	$(MAKE) -C build

build/Makefile:
	touch *
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	for f in *.[ch] ; do ln -s ../$$f build/$$f ; done ; \
	cd build ; \
	../configure $(CONFIGURE_OPTS)

clean:
	rm -rf build

romfs:
	$(ROMFSINST) -e CONFIG_USER_AT_AT build/at /bin/at
	$(ROMFSINST) -e CONFIG_USER_AT_ATD build/atd /bin/atd
	$(ROMFSINST) -e CONFIG_USER_AT_ATRUN build/atrun /bin/atrun

.PHONY: all clean romfs
