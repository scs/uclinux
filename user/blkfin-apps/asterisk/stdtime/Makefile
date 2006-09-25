OBJS=localtime.o

OBJSDLL = $(OBJS:.o=.pic.o)

# Special compilation rules to support ansi2knr and libtool.
.SUFFIXES: .lo .la .c .o .pic.o

.c.pic.o:
	$(CC) -c $(CFLAGS) -o $@ $*.c

ifeq ($(CONFIG_BLACKFIN_USE_FDPIC),y)
all: libtime.a libtime.so
else
all: libtime.a
endif

libtime.a: $(OBJS)
	$(AR) rv $@ $(OBJS)
	$(RANLIB) $@

# libtime.so
ifeq ($(CONFIG_BLACKFIN_USE_FDPIC),y)
libtime.so: $(OBJSDLL)
	$(CC) $(CFLAGS) -shared -Wl,-soname,libtime.so -o libtime.so \
	$(OBJSDLL) -lm -lc
endif

install:

clean:
	rm -f libtime.a *.o test .depend *.so

depend: .depend

.depend:
	../mkdep $(CFLAGS) *.c

test: test.c
	${CC} ${CFLAGS} -o test test.c

ifneq ($(wildcard .depend),)
include .depend
endif
