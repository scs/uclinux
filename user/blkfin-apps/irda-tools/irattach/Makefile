
EXEC = irattach dongle_attach

all: $(EXEC)

irattach: irattach.o util.o
	$(CC) $(LDFLAGS) -o $@ irattach.o util.o $(LDLIBS$(LDLIBS_$@))

dongle_attach: dongle_attach.o
	$(CC) $(LDFLAGS) -o $@ dongle_attach.o $(LDLIBS$(LDLIBS_$@))

romfs:
	$(ROMFSINST) /bin/irattach
	$(ROMFSINST) /bin/dongle_attach

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

