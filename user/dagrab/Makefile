### UCLINUX CHANGES: START ###
uclinux: dagrab
romfs:
	$(ROMFSINST) -d -e CONFIG_USER_DAGRAB_DAGRAB /usr/bin/dagrab
### UCLINUX CHANGES:  END  ###

# Makefile for dagrab

# Note: PTHREAD support is optional, you can comment it out
################################################################################

PREFIX=/usr/local
CC ?= gcc
CFLAGS ?= -O
CFLAGS += -W -Wall -DPTHREAD
LDFLAGS ?= -O -s
LIBS = -lpthread

all:	dagrab

SOURCES=cddb.c dagrab.c jitter.c jit_in.c print.c err.c
OBJ= 	$(SOURCES:.c=.o)

%.o:	%.c
	$(CC) $(CFLAGS) -c $< -o $@

cddb.o:		main.h const.h version.h dagrab.h
dagrab.o:	main.h const.h jit_in.h jitter.h cddb.h print.h err.c Makefile
jitter.o:	main.h dagrab.h print.h const.h
jit_in.o:	main.h dagrab.h const.h print.h
print.o:	main.h const.h dagrab.h cddb.h version.h
err.o:		dagrab.h main.h

dagrab:	$(OBJ) Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) $(LIBS) -o dagrab

clean:
	rm -f dagrab *.o *.wav *.mp[23] *.ogg .*swp *~ gmon.out tags

install: dagrab
	strip dagrab
	mkdir -p $(INSTROOT)/${PREFIX}/bin; mkdir -p $(INSTROOT)/${PREFIX}/man/man1
	cp dagrab $(INSTROOT)/${PREFIX}/bin
	cp grab $(INSTROOT)/${PREFIX}/bin
	cp dagrab.1 $(INSTROOT)/${PREFIX}/man/man1
