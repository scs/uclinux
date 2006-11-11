EXEC = pngview
OBJS = pngview.o

CFLAGS   += -Wall
CPPFLAGS += -I$(ROOTDIR)/lib/libpng -I$(ROOTDIR)/lib/zlib
LDFLAGS  += -L$(ROOTDIR)/lib/libpng -L$(ROOTDIR)/lib/zlib
LDLIBS   += -lpng -lz -lm

all: $(EXEC)

$(EXEC): $(OBJS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

pngview.o: pngview.c
