EXEC=mpc

srcdir = .
top_srcdir = ..
top_builddir = ..

DEFS = -DHAVE_CONFIG_H
DEFAULT_INCLUDES =  -I. -I$(srcdir) -I$(top_builddir)
LIBS =  -lnsl

CSRC = libmpdclient.c  main.c list.c  password.c  charConv.c status.c util.c command.c options.c net.c
OBJS=$(patsubst %.c,%.o, $(CSRC))

CFLAGS += -Wall #-O0

FLTFLAGS += -s 24576

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS) $(LIBS)


$(OBJS): %.o : %.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CFLAGS) -c $< -o $@




romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.gdb *.elf *.o

