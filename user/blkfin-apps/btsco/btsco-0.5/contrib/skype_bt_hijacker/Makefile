CC=gcc
CFLAGS=-O2 -Wall
LIBADD_DL=-ldl
OPTIONS=-shared -fpic

INSTALLBINFILES=btscorunner skype_pickup.py \
	skype_bt_hijacker_onclose skype_bt_hijacker_onopen \
	skype_bt_hijacker

PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
LIBDIR=$(PREFIX)/lib

all:
	$(CC) $(CFLAGS) $(LIBADD_DL) $(OPTIONS) skype_bt_hijacker.c -o libskype_bt_hijacker.so

install:
	echo $(BINDIR)
	# install --mode=755 libskype_bt_hijacker.so $(LIBDIR)
	# I know this is wrong. This will go away when it's mature.
	install --mode=755 libskype_bt_hijacker.so $(BINDIR)
	install --mode=755 $(INSTALLBINFILES) $(BINDIR)
	
clean:
#	rm -f *~
	rm -f libskype_bt_hijacker.so
