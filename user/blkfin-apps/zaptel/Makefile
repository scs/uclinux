EXTRA_CFLAGS+=-DSTANDALONE_ZAPATA -DEXPORT_SYMTAB 
TZOBJS=zonedata.o tonezone.o
LIBTONEZONE=libtonezone.a
CFLAGS+=-I. -Wall -DBUILDING_TONEZONE 

CONFIG_FILE=/etc/zaptel.conf
CFLAGS+=-DZAPTEL_CONFIG=\"$(CONFIG_FILE)\"

KDIR=$(ROOTDIR)/linux-2.6.x
PWD=$(shell pwd)

FLTFLAGS=-s 32000

all: apps
	

apps: libtonezone.a ztcfg

tones.h: gendigits
	./gendigits

gendigits: gendigits.o
	$(CC) -o gendigits gendigits.o -lm

zonedata.o: zonedata.c
	$(CC) $(CFLAGS) -c -o zonedata.o zonedata.c

tonezone.o: tonezone.c
	$(CC) $(CFLAGS) -c -o tonezone.o tonezone.c

libtonezone.a: $(TZOBJS)
	ar rcs libtonezone.a $(TZOBJS)

ztcfg.o: ztcfg.c
	$(CC) $(CFLAGS) -c -o ztcfg.o ztcfg.c

ztcfg: ztcfg.o libtonezone.a
	$(CC) $(CFLAGS) -o ztcfg ztcfg.o libtonezone.a -lm $(LDFLAGS)

clean:
	rm -f *.o *.ko *.lo gendigits tor2fw.h tones.h ztcfg

romfs:
	cp ./zaptel.conf $(ROMFSDIR)/etc/
	chmod u+x ztcfg 
	cp ./ztcfg $(ROMFSDIR)/bin
	
install:
	$(MAKE) -C $(KDIR) INSTALL_MOD_PATH=$(IDIR) \
	SUBDIRS=$(PWD) modules_install

