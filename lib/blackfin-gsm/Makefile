# Makefile for  Blackfin port of GSM
# David Rowe 6 June 2006

PROJ=blackfin-gsm
VERSION=0.1

# extract dir from /path/to/dir
RELCWD = $(shell pwd | sed -e "s/.*\///")

# these will override flags of same name in the gsm Makefile

CC=bfin-uclinux-gcc
CCFLAGS=-c -O2
AR=bfin-uclinux-ar
LDFLAGS=-Wl,-elf2flt=-s100000 -lm
FLAGS=CC=$(CC) CCFLAGS='$(CCFLAGS)' AR=$(AR) WAV49=

all: tgsm

gsm/lib/libgsm.a:
	make $(FLAGS) -C gsm lib/libgsm.a

tgsm: tgsm.c gsm/lib/libgsm.a
	$(CC) -I. tgsm.c -o tgsm gsm/lib/libgsm.a samcycles.c -Wall $(LDFLAGS)

romfs:


clean:
	make -C gsm clean
	rm -f tgsm *.gdb male.* tarball.tar
	find . -name "*~" | xargs rm -f
	find . -name "*.s" | xargs rm -f

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


