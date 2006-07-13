# Makefile for Blackfin sample(s)
# David Rowe 
# 12 May 2006

# extract dir from /path/to/dir
RELCWD = $(shell pwd | sed -e "s/.*\///")

dot: dot.c 
	bfin-uclinux-gcc -Wl,-elf2flt -O0 dot.c -o dot_O0
	bfin-uclinux-gcc -Wl,-elf2flt -O1 dot.c -o dot_O1
	bfin-uclinux-gcc -Wl,-elf2flt -O2 dot.c -o dot_O2
	bfin-uclinux-gcc -Wl,-elf2flt -O3 dot.c -o dot_O3
	bfin-uclinux-gcc -Wl,-elf2flt -O3 -fomit-frame-pointer dot.c -o dot_O0
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
