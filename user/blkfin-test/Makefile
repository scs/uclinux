
dir_y =
dir_y += rtc-test
dir_y += dpmc-test
#dir_y += spi0app
#dir_y += usb_test
#dir_y += sport_test
dir_y += audio_test
dir_y += video_test

all:
	for i in $(dir_y) ; do  make -C $$i || exit $? ; done

romfs:
	for i in $(dir_y) ; do  make -C $$i romfs || exit $? ; done

clean:
	-for i in $(dir_y) ; do \
		[ ! -d $$i ] || make -C $$i clean; \
	done

#
#	$(CC) $(LDFLAGS) -o $@ $@.o $(LDLIBS)
#
#romfs:
#	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_RTC /bin/rtc_test
#
#clean:
#	rm -rf *.elf *.gdb *.o $(EXECS)
