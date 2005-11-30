EXEC=ltest
srcdir = .
top_srcdir = ..
top_builddir = ..
INCLUDES = -I$(top_srcdir)/libaudiofile
CSRC=linuxtest.c
OBJS=$(patsubst %.c,%.o, $(CSRC))

LDADD = $(top_builddir)/libaudiofile/libaudiofile.la

DEFS = -DHAVE_CONFIG_H
DEFAULT_INCLUDES =  -I. -I$(srcdir) -I$(top_builddir)
LIBS = -lm
CFLAGS = -g -O2



all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS) $(EXTRALIBS)



$(OBJS): %.o : %.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CFLAGS) -c $< -o $@




romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.gdb *.elf *.o

