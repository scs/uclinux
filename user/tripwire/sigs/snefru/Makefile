# $Id$
#
# Makefile for snefru wrapper
#
# Gene Kim
# Purdue University
# October 18, 1992
#

all:	snefru.o

.c.o:
	$(CC) $(CFLAGS) -c $<
	
clean:
	-rm -rf *.o .pure

snefru.o: ../../include/byteorder.h
