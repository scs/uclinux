EXEC = flashw
OBJS = flashw.o
CFLAGS +=-I.

all: $(EXEC)

mtd:
	ln -sf $(ROOTDIR)/$(LINUXDIR)/include/mtd mtd

flashw.o:mtd

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS$(LDLIBS_$@))

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o mtd

