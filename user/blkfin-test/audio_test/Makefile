
all:  echo2 ossrec ossplay audio_test

dsp.o:dsp.c
	$(CC) $(CFLAGS) -o $@ -c dsp.c

ossrec.o:ossrec.c dsp.h
	$(CC) $(CFLAGS) -o $@ -c ossrec.c 

ossplay.o:ossplay.c dsp.h
	$(CC) $(CFLAGS) -o $@ -c ossplay.c

ossrec: dsp.o ossrec.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ ossrec.o dsp.o $(LDLIBS) 

ossplay: dsp.o ossplay.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ ossplay.o dsp.o $(LDLIBS) 

ossloop: dsp.o ossloop
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ ossloop.o dsp.o $(LDLIBS) 

echo2: echo2.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ echo2.c $(LDLIBS) 

audio_test: audio_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ audio_test.c $(LDLIBS) 

romfs:
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_AUDIOTEST /bin/ossrec
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_AUDIOTEST /bin/ossplay
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_AUDIOTEST /bin/echo2
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_AUDIOTEST /bin/audio_test

clean:
	rm -f *.elf *.gdb *.o audio_test ossrec ossplay echo2 lala
