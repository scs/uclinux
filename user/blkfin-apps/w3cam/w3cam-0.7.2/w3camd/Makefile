# Generated automatically from Makefile.in by configure.
#
# makefile for w3camd
#
prefix=/usr/local
sbindir=/usr/local/sbin

CFLAGS = -O2 -Wall -I/usr/local/include -I/usr/local/X11/include -I.. -I. -I/usr/local/include -g -DDEBUG -DCAM_PORT=8999 -D_REENTRANT
CC = gcc

default: w3camd

OBJ = w3camd.o w3socket.o w3v4l.o w3http.o w3jpeg.o

%.o: %.c
	$(CC) $(CFLAGS) -c $<

w3camd: $(OBJ)
	$(CC) -o $@ $(OBJ) -lpthread -ljpeg

install:
	install w3camd $(sbindir)/

clean:
	rm -f *.o w3camd

README: index.html
	lynx -dump http://www/~rasca/w3cam/w3camd/index.html >README

