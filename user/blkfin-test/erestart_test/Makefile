EXEC = erestart

all: $(EXEC)

$(EXEC): erestart.c
	$(CC) $(LDFLAGS) -O -o $@ erestart.c 

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
 
