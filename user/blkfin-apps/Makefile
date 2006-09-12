dir_y = 
dir_$(CONFIG_USER_BLACKFIN_PPIFCDCGI)             	+= ppifcd-cgi
dir_$(CONFIG_USER_BLACKFIN_GDB)             		+= gdbserver
dir_$(CONFIG_USER_BLACKFIN_LINPHONE)			+= linphone
dir_$(CONFIG_USER_BLKFIN_APPS_DEVFBAPP_DEVTEST)         += devfbapp 
dir_$(CONFIG_USER_BLKFIN_APPS_DEVVOUT_DEVOUT)		+= devvoutapp
dir_$(CONFIG_USER_INETUTILS_RCP)			+= inetutils
dir_$(CONFIG_USER_INETUTILS_RSH)			+= inetutils
dir_$(CONFIG_USER_INETUTILS_RSHD)			+= inetutils
dir_$(CONFIG_USER_SQLITE)				+= sqlite-3.2.6
dir_$(CONFIG_USER_LMBENCH)				+= lmbench3
dir_$(CONFIG_USER_BLACKFIN_STRACE)			+= strace
dir_$(CONFIG_USER_BF561_COREBLD)			+= corebld
dir_$(CONFIG_USER_OPROFILE)				+= oprofile
dir_$(CONFIG_USER_FLTHDR)				+= flthdr
dir_$(CONFIG_USER_YAFFS_UTILS)				+= yaffs-utils
dir_$(CONFIG_USER_POUND)                                += pound
dir_$(CONFIG_USER_IRATTACH)                             += irattach
dir_$(CONFIG_USER_JPEGVIEW)                             += jpegview
dir_$(CONFIG_USER_BLACKFIN_WATCHDOGD)				+= watchdogd
dir_$(CONFIG_USER_ASTERISK)				+= asterisk

all:
	[ -n "${CONFIG_USER_ZAPTEL}" ] &&  make -C zaptel
	[ -n "${CONFIG_USER_THREADSTACK}" ] && make -C threadstack-0.1
	for i in $(sort $(dir_y)) ; do  make -C $$i || exit $? ; done

romfs:
	make -C zaptel romfs
	for i in $(sort $(dir_y)) ; do  make -C $$i romfs || exit $? ; done

clean:
	for i in $(sort $(dir_y)) ; do \
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
