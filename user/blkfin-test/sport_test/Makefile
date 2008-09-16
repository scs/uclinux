EXEC = sport_test
OBJS = sport_test.o

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS$(LDLIBS_$@))

romfs:
	$(ROMFSINST) /bin/$(EXEC)
	$(ROMFSINST) /sample.wav

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
 
