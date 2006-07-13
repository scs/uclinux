# Makefile for Blackfin sample(s)
# David Rowe 
# 12 May 2006

# extract dir from /path/to/dir
RELCWD = $(shell pwd | sed -e "s/.*\///")

CC      = bfin-uclinux-gcc
CFLAGS  = -Wall
LDFLAGS = -Wl,-elf2flt

dot: dot.c
	$(CC) $(CFLAGS) $(LDFLAGS) -O0 dot.c -o dot_O0
	$(CC) $(CFLAGS) $(LDFLAGS) -O1 dot.c -o dot_O1
	$(CC) $(CFLAGS) $(LDFLAGS) -O2 dot.c -o dot_O2
	$(CC) $(CFLAGS) $(LDFLAGS) -O3 dot.c -o dot_O3
	$(CC) $(CFLAGS) $(LDFLAGS) -O3 -fomit-frame-pointer dot.c -o dot_O0

dist:
	@if [ ! -d ../$(PROJ)-$(VERSION) ]; then \
		echo "Please change directory name to $(PROJ)-$(VERSION)"; \
		exit 1; \
	fi 

	# remove unneeded files
	rm -f *~ cycles

	# create tar ball containing only directories we need
	cd ..; tar vczf $(PROJ)-$(VERSION).tar.gz $(RELCWD)
	@echo
	@echo "Tar ball created in ../"
	ls -lh ../$(PROJ)-$(VERSION).tar.gz

clean:
	rm -f *.gdb dot_*
