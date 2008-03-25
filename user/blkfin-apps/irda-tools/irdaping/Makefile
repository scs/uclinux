
EXEC = irdaping 

all: $(EXEC)

irattach: irdaping.o
	$(CC) $(LDFLAGS) -o $@ irdaping.o $(LDLIBS$(LDLIBS_$@))

romfs:
	$(ROMFSINST) /bin/irdaping

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

