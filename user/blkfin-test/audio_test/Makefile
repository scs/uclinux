
all: audio_test 

audio_test: audio_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ audio_test.c $(LDLIBS) 
romfs:
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_RTC /bin/audio_test
clean:
	rm -f *.elf *.gdb *.o audio_test

