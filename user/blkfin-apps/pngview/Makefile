EXEC = pngview
OBJS = pngview.o

CFLAGS   += -Wall
LDLIBS   += $(shell $(CONFIGURE_HOST)-pkg-config --libs libpng)

all: $(EXEC)

$(EXEC): $(OBJS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

pngview.o: pngview.c
