dir_y =
dir_$(CONFIG_USER_BLACKFIN_GDB)             += gdbserver

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
