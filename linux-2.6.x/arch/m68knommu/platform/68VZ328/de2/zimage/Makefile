
# Runtime parameters
UNZIP_ADDRESS := $(shell [ -f $(ROOTDIR)/$(LINUXDIR)/System.map ] && grep ' _stext$$' $(ROOTDIR)/$(LINUXDIR)/System.map | cut -d' ' -f1)
START_ADDRESS := $(shell [ -f $(ROOTDIR)/$(LINUXDIR)/System.map ] && grep ' _start$$' $(ROOTDIR)/$(LINUXDIR)/System.map | cut -d' ' -f1)

# Compiler and associated tools filenames.
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld
OBJCOPY = $(CROSS_COMPILE)objcopy

# Flags.
AFLAGS = -m68000 -Wall -I$(ROOTDIR)/$(LINUXDIR)/include
CFLAGS = -m68000 -Wall -O2 --omit-frame-pointer -I$(ROOTDIR)/$(LINUXDIR)/include
LFLAGS = -m68000 -nostdlib -Wl,-Map=$(basename $@).map

#
# Targets
#

OBJECTS = \
	main.o \
	misc.o

all: $(IMAGEDIR)/zImage.bin

crt0.o: crt0.S
	$(CC) $(AFLAGS) -o $@ -c $+

image.o: $(IMAGEDIR)/image.bin
	tmpimage=_tmp_$$$$image; \
	cat $+ | gzip -f -9 > $$tmpimage; \
	$(LD) -r -o $@ -b binary $$tmpimage; \
	rm -f $$tmpimage

$(IMAGEDIR)/zImage.bin: crt0.o image.o ${OBJECTS}
	tmpprog=_tmp_$$$$prog; \
	tmplnk=_tmp_$$$$lnk; \
	cp image.ld $$tmplnk; \
	echo "PROVIDE (output_data = 0x$(UNZIP_ADDRESS));" >> $$tmplnk; \
	echo "PROVIDE (start_image = 0x$(START_ADDRESS));" >> $$tmplnk; \
	$(CC) $(LFLAGS) -T $$tmplnk -o $$tmpprog ${OBJECTS}; \
	$(OBJCOPY) -O binary -j .text -j .data $$tmpprog $@; \
	rm -f $$tmpprog $$tmplnk

clean:
	rm -f *.o _tmp_*
