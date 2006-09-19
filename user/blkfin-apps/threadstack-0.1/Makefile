# Makefile for thread stack functions
# David Rowe 
# 12 May 2006

# Default configuration is for the Blackfin uClinux platform
# Chnage the following to suit your target:
#
# 1/ LIBPTHREAD_PATH
# 2/ CC 
# 3/ LDFLAGS

LIBPTHREAD_PATH  = $(ROOTDIR)/uClibc/libpthread/linuxthreads
CC ?= bfin-uclinux-gcc

CFLAGS += \
	-I $(LIBPTHREAD_PATH) \
	-I $(LIBPTHREAD_PATH)/sysdeps/pthread/ \
	-I $(LIBPTHREAD_PATH)/sysdeps/bfin

PROJ=threadstack
VERSION=0.1

# extract dir from /path/to/dir
RELCWD = $(shell pwd | sed -e "s/.*\///")

all: test_threadstack

test_threadstack: test_threadstack.c threadstack.o
	$(CC) $(CFLAGS) test_threadstack.c threadstack.o \
	-o test_threadstack $(LDFLAGS) -lpthread

threadstack.o: threadstack.c
	$(CC) $(CFLAGS) -c threadstack.c -o threadstack.o

romfs:



dist:
	@if [ ! -d ../$(PROJ)-$(VERSION) ]; then \
	  echo "Please change directory name to $(PROJ)-$(VERSION)"; \
	  exit 1; \
        fi 

	# remove unneeded files
	rm -f *~ test_threadstack *.o

	# create tar ball containing only directories we need
	cd ..; tar vczf $(PROJ)-$(VERSION).tar.gz $(RELCWD)
	@echo
	@echo "Tar ball created in ../"
	ls -lh ../$(PROJ)-$(VERSION).tar.gz

clean distclean:
	rm -f *.o *.gdb test_threadstack
