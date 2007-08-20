# Makefile for Blackfin uClinux port of G729A(B)
# David Rowe 15 October June 2006

SUBDIRS = src.orig src.simgot src.fdpic test

PROJ=g729ab
VERSION=0.1

# extract dir from /path/to/dir
RELCWD = $(shell pwd | sed -e "s/.*\///")

# these will override flags of same name in the gsm Makefile

# ip addr of test machine
IPADDR = 10.99.22.116
TEST_PROG = g729ab_test g729ab_testsimgot g729ab_testfdpic g729ab_testfdpic_so

all:
	$(MAKE) -C test

DIRS_CLEAN := $(patsubst %,%_clean,$(SUBDIRS))
clean: $(DIRS_CLEAN)
	find . '(' -name '*~' -o -name '*.s' ')' | xargs rm -f
%_clean:
	$(MAKE) -C $(patsubst %_clean,%,$@) clean

install: all
	[ -d $(DESTDIR)/usr/lib ] || mkdir -p $(DESTDIR)/usr/lib
	[ -d $(DESTDIR)/usr/include ] || mkdir -p $(DESTDIR)/usr/include
ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
	cp -f src.fdpic/libg729ab.a $(DESTDIR)/usr/lib 
	cp -f src.fdpic/libg729ab.so $(DESTDIR)/usr/lib
else
	cp -f src.orig/libg729ab.a $(DESTDIR)/usr/lib
endif	
	cp -f include/g729ab_codec.h $(DESTDIR)/usr/include

dist:
	@if [ ! -d ../$(PROJ)-$(VERSION) ]; then \
	  echo "Please change directory name to $(PROJ)-$(VERSION)"; \
	  exit 1; \
        fi 

	# remove unneeded files
	make clean

	# create tar ball containing only directories we need
	cd ..; tar vczf $(PROJ)-$(VERSION).tar.gz $(RELCWD)
	@echo
	@echo "Tar ball created in ../"
	ls -lh ../$(PROJ)-$(VERSION).tar.gz

check test: all
	if [ $(IPADDR) ]; then \
		echo "Please give ip addr of test machine" \
		exit 1; \
	fi
	rcp -r test/test_data root@$(IPADDR):/var
	rcp test/quick.sh root@$(IPADDR):/var
	rcp test/alltests.sh root@$(IPADDR):/var
	rcp src.fdpic/libg729ab.so root@$(IPADDR):/lib
	for file in $(TEST_PROG); do \
		rcp test/$$file root@$(IPADDR):/var; \
		rsh -lroot $(IPADDR) /var/quick.sh /var/$$file; \
	done

.PHONY: all check clean install test
