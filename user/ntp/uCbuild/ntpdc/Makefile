
PROG=ntpdc

VPATH=	../../$(PROG)

# config.h
CFLAGS += -DHAVE_CONFIG_H -I../include

# ntp headers
CFLAGS += -I../../include

SRCS=	ntpdc.c ntpdc_ops.c

OBJS=	version.o $(SRCS:.c=.o)
LIBS=	../libntp/libntp.a ../libparse/libparse.a

version.c: $(SRCS)
	env CSET=`cat ../../version` ../../scripts/mkver $(PROG)

$(PROG): $(OBJS) $(LIBS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) -lm

all: $(PROG)

romfs:
	$(ROMFSINST) /bin/$(PROG)

clean:
	rm -f $(PROG) $(PROG).gdb version.c $(LIB) $(OBJS) .version
