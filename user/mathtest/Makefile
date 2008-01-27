
EXEC = mtst mtstf j0tst nantst powtst

CFLAGS += -g -Os

all: $(EXEC)
	# cp $(EXEC) $(ROOTDIR)/romfs/bin/

mtst: mtst.o
	$(CC) $(LDFLAGS) -o $@ mtst.o -lm $(LDLIBS)

mtstf: mtstf.o
	$(CC) $(LDFLAGS) -o $@ mtstf.o -lm $(LDLIBS)

j0tst: j0tst.o
	$(CC) $(LDFLAGS) -o $@ j0tst.o -lm $(LDLIBS)

nantst: nantst.o
	$(CC) $(LDFLAGS) -o $@ nantst.o -lm $(LDLIBS)

powtst: powtst.o
	$(CC) $(LDFLAGS) -o $@ powtst.o -lm $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/mtst
	$(ROMFSINST) /bin/mtstf
	$(ROMFSINST) /bin/j0tst
	$(ROMFSINST) /bin/nantst
	$(ROMFSINST) /bin/powtst

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

