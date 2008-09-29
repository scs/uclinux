#!/usr/bin/make

######################################################################
# YOU SHOULD NOT NEED TO TOUCH ANYTHING BELOW THIS LINE
######################################################################

ifndef KERNEL_DIR
KERNEL_DIR=/usr/src/linux
endif

IPSET_VERSION:=2.2.9a

PREFIX:=/usr/local

PREFIX:=/
DESTDIR:=$(ROMFSDIR)
SETTYPES:=iphash

LIBDIR:=$(PREFIX)/lib
BINDIR:=$(PREFIX)/bin
MANDIR:=$(PREFIX)/man
INCDIR:=$(PREFIX)/include
IPSET_LIB_DIR:=$(LIBDIR)/ipset

# directory for new iptables releases
RELEASE_DIR:=/tmp

COPT_FLAGS:=-O2
CFLAGS:=$(COPT_FLAGS) -Wall -Wunused -I$(KERNEL_DIR)/include -I. # -g -DIPSET_DEBUG #-pg # -DIPTC_DEBUG
SH_CFLAGS:=$(CFLAGS) -fPIC
ALL_SETTYPES:=ipmap portmap macipmap iphash nethash iptree ipporthash

PROGRAMS=ipset
SHARED_LIBS=$(foreach T, $(SETTYPES),libipset_$(T).so)
INSTALL=$(DESTDIR)$(BINDIR)/ipset #$(DESTDIR)$(MANDIR)/man8/ipset.8
INSTALL+=$(foreach T, $(SETTYPES), $(DESTDIR)$(LIBDIR)/ipset/libipset_$(T).so)

all: $(PROGRAMS) $(SHARED_LIBS)

install: all $(INSTALL)

clean: $(EXTRA_CLEANS)
	rm -rf $(PROGRAMS) $(SHARED_LIBS) *.o *~

#The ipset(8) self
ipset.o: ipset.c
	$(CC) $(CFLAGS) -DIPSET_VERSION=\"$(IPSET_VERSION)\" -DIPSET_LIB_DIR=\"$(IPSET_LIB_DIR)\" -c -o $@ $<

ipset: ipset.o
	$(CC) $(CFLAGS) -ldl -rdynamic -o $@ $^

#Pooltypes
ipset_%.o: ipset_%.c
	$(CC) $(SH_CFLAGS) -o $@ -c $<

libipset_%.so: ipset_%.o
	$(LD) -shared -o $@ $<

$(DESTDIR)$(LIBDIR)/ipset/libipset_%.so: libipset_%.so
	@[ -d $(DESTDIR)$(LIBDIR)/ipset ] || mkdir -p $(DESTDIR)$(LIBDIR)/ipset
	cp $< $@

$(DESTDIR)$(BINDIR)/ipset: ipset
	@[ -d $(DESTDIR)$(BINDIR) ] || mkdir -p $(DESTDIR)$(BINDIR)
	cp $< $@

$(DESTDIR)$(MANDIR)/man8/ipset.8: ipset.8
	@[ -d $(DESTDIR)$(MANDIR)/man8 ] || mkdir -p $(DESTDIR)$(MANDIR)/man8
	cp $< $@

romfs: install
