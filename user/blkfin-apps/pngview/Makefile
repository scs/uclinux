EXEC = pngview
OBJS = pngview.o

CFLAGS   += -Wall
CPPFLAGS += -I$(ROOTDIR)/lib/libpng -I$(ROOTDIR)/lib/zlib
LDLIBS   += -L$(ROOTDIR)/lib/libpng -lpng

all: $(EXEC)

$(EXEC): $(OBJS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

pngview.o: pngview.c
