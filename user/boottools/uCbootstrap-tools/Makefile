CC = gcc
CFLAGS = -W -Wall -O2 -g
CPPFLAGS = -I/usr/src/linux/include/

EXECS = uCmkimage uCheader
OBJS = md5.o

all:  md5.o $(EXECS)

md5.o:
	$(CC) -c md5.c

$(EXECS):
	$(CC) -o $@ $@.c $(OBJS)

clean:
	-rm -f $(EXECS) $(OBJS)

