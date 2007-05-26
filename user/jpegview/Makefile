EXEC = jpegview 
OBJS = jpegview.o

CFLAGS += -I $(ROOTDIR)/lib/libjpeg 
LDLIBS += -L $(ROOTDIR)/lib/libjpeg -ljpeg

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

jpegview.o: jpegview.c 

