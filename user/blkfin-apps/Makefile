dir_y =
dir_$(CONFIG_USER_BLACKFIN_PPIFCDCGI)             	+= ppifcd-cgi
dir_$(CONFIG_USER_BLACKFIN_GDB)             		+= gdbserver
dir_$(CONFIG_USER_BLACKFIN_LINPHONE)			+= linphone
dir_$(CONFIG_USER_BLKFIN_APPS_DEVFBAPP_DEVTEST)         += devfbapp 
dir_$(CONFIG_USER_BLKFIN_APPS_DEVVOUT_DEVOUT)		+= devvoutapp
dir_$(CONFIG_USER_INETUTILS_RCP)			+= inetutils
dir_$(CONFIG_USER_INETUTILS_RSH)			+= inetutils
dir_$(CONFIG_USER_INETUTILS_RSHD)			+= inetutils
all:
	for i in $(sort $(dir_y)) ; do  make -C $$i || exit $? ; done

romfs:
	for i in $(sort $(dir_y)) ; do  make -C $$i romfs || exit $? ; done

clean:
	-for i in $(sort $(dir_y)) ; do \
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
