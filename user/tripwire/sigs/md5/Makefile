# $Id$
#
# Makefile for md5 wrapper
#
# Gene Kim
# Purdue University
# October 18, 1992
#

all:	md5.o md5wrapper.o

.c.o:
	$(CC) $(CFLAGS) -c $<
	
clean:
	-rm -rf md5.o md5wrapper.o .pure

md5.o: ../../include/byteorder.h
md5wrapper.o: ../../include/byteorder.h
