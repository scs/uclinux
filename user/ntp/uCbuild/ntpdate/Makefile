
PROG=ntpdate

VPATH=	../../$(PROG)

# config.h
CFLAGS += -DHAVE_CONFIG_H -I../include

# ntp headers
CFLAGS += -I../../include

SRCS=	ntpdate.c

OBJS=	version.o $(SRCS:.c=.o)
LIBS=	../libntp/libntp.a ../libparse/libparse.a

version.c: $(SRCS)
	CSET=`cat ../../version`		;\
	DATE=`LC_TIME=C date`			;\
	echo '#include <config.h>' > version.c	;\
	echo "const char * Version = \"$(PROG) \" VERSION \"@$$CSET $$DATE (uCbuild)\";" >> version.c

$(PROG): $(OBJS) $(LIBS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) -lm

all: $(PROG)

romfs:
	$(ROMFSINST) /bin/$(PROG)

clean:
	rm -f $(PROG) $(PROG).gdb version.c $(LIB) $(OBJS) .version
