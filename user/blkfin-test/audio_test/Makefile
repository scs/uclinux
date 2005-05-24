
all:  echo2 ossrec ossplay 

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

romfs:
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_RTC /bin/ossrec
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_RTC /bin/ossplay
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_RTC /bin/echo2

clean:
	rm -f *.elf *.gdb *.o audio_test ossrec ossplay echo2 lala

#
#  Deprecated..  full-duplex operation doesn't work with current driver.
#
audio_test: audio_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ audio_test.c $(LDLIBS) 
audio_test_romfs:
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_RTC /bin/audio_test

