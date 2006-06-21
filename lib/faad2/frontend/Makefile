EXEC=faad

srcdir = .
top_srcdir = ..
top_builddir = ..
MPD_CFLAGS = -Wall

#FAAD_LIBS =   -lm  -lmad -lidtag -lz -lflac -lfaad -lmp4ff -lmodules -laudiofile -lmodules -laudiofile -lm -ltremor  

FAAD_SOURCES = \
	audio.c \
	main.c \
	../common/faad/getopt.c

CSRC = $(FAAD_SOURCES)
DEFS = -DHAVE_CONFIG_H

DEFAULT_INCLUDES = -I. -I.. -I$(ROOTDIR)/lib/faad2/include -I$(ROOTDIR)/lib/faad2/common/faad -I$(ROOTDIR)/lib/faad2/common/mp4ff

OBJS=$(patsubst %.c,%.o, $(CSRC))


EXTRALIBS = $(FAAD_LIBS)


CFLAGS += $(FAAD_CFLAGS)

LDLIBS+= $(ROOTDIR)/lib/lib/libfaad.a $(ROOTDIR)/lib/lib/libmp4ff.a
all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS) $(EXTRALIBS)

$(OBJS): %.o : %.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CFLAGS) -c $< -o $@

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.gdb *.elf *.elf2flt *.o ../common/faad/getopt.o
