# Generated automatically from Makefile.in by configure.

KERNEL_HEADERS=-I/usr/src/linux/include

INCLUDE=-I../libbridge $(KERNEL_HEADERS) 
LIBS= -L ../libbridge -lbridge

prefix=/usr/local
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
sbindir=${exec_prefix}/sbin
mandir=${prefix}/man

INSTALL=/usr/bin/install -c


common_SOURCES= brctl_cmd.c brctl_disp.c 
brctl_SOURCES=  brctl.c $(common_SOURCES)
brctld_SOURCES= brctld.c $(common_SOURCES)

common_OBJECTS= $(common_SOURCES:.c=.o)
brctl_OBJECTS= $(brctl_SOURCES:.c=.o)
brctld_OBJECTS= $(brctld_SOURCES:.c=.o)

OBJECTS= $(common_OBJECTS) $(brctl_OBJECTS) $(brctld_OBJECTS)

PROGRAMS= brctl 
#
# this looks too hard to get going, so I don't worry about it.
#brctld

all:	$(PROGRAMS)

install: $(PROGRAMS)
	mkdir -p $(DESTDIR)$(sbindir)
	$(INSTALL) -m 755 $(PROGRAMS) $(DESTDIR)$(sbindir)

brctl:	$(brctl_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(brctl_OBJECTS) $(LIBS) $(LDLIBS)

brctld:	$(brctld_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(brctld_OBJECTS) $(LIBS) $(LDLIBS)

%.o: %.c brctl.h
	$(CC) $(CFLAGS) $(INCLUDE) -c $< 

clean:
			rm -f *.o
			rm -f brctl
			rm -f brctld
			rm -f core

