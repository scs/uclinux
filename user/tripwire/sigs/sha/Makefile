# $Id$
#
# Makefile for SHA wrapper
#
# Gene Kim
# Purdue University
# August 10, 1993
#

all:	sha.o shawrapper.o

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	-rm -rf *.o .pure

sha.o: ../../include/byteorder.h
shawrapper.o: ../../include/byteorder.h
