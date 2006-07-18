# Makefile for Blackfin sample(s)
# David Rowe 
# 12 May 2006

# extract dir from /path/to/dir
RELCWD = $(shell pwd | sed -e "s/.*\///")

CC      = bfin-uclinux-gcc
CFLAGS  = -Wall
LDFLAGS = -Wl,-elf2flt
TARGET  = 10.64.204.102

TESTS   = dot_O0 dot_O1 dot_O2 dot_O3 dot_O3-frame

all: $(TESTS)

# XXX: should make $(TESTS) have a real binding to dot.c ...
$(TESTS): dot
dot: dot.c
	$(CC) $(CFLAGS) $(LDFLAGS) -O0 dot.c -o dot_O0
	$(CC) $(CFLAGS) $(LDFLAGS) -O1 dot.c -o dot_O1
	$(CC) $(CFLAGS) $(LDFLAGS) -O2 dot.c -o dot_O2
	$(CC) $(CFLAGS) $(LDFLAGS) -O3 dot.c -o dot_O3
	$(CC) $(CFLAGS) $(LDFLAGS) -O3 -fomit-frame-pointer dot.c -o dot_O3-frame

check test:
	rcp dot_O* root@$(TARGET):/home/
	rsh -l root $(TARGET) /home/dot_O0 > out_O0
	rsh -l root $(TARGET) /home/dot_O1 > out_O1
	rsh -l root $(TARGET) /home/dot_O2 > out_O2
	rsh -l root $(TARGET) /home/dot_O3 > out_O3
	rsh -l root $(TARGET) /home/dot_O3-frame > out_O3-frame

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

check_in:
	rm -f */gdb dot_*

clean:
	rm -f *.gdb dot_* out_O*

.PHONY: all dot check test dist check_in clean
