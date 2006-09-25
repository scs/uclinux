dir_y = 
dir_$(CONFIG_USER_BLACKFIN_PPIFCDCGI)            += ppifcd-cgi
dir_$(CONFIG_USER_BLACKFIN_GDB)                  += gdbserver
dir_$(CONFIG_USER_BLACKFIN_LINPHONE)             += linphone
dir_$(CONFIG_USER_BLKFIN_APPS_DEVFBAPP_DEVTEST)  += devfbapp
dir_$(CONFIG_USER_BLKFIN_APPS_DEVVOUT_DEVOUT)    += devvoutapp
dir_$(CONFIG_USER_INETUTILS_RCP)                 += inetutils
dir_$(CONFIG_USER_INETUTILS_RSH)                 += inetutils
dir_$(CONFIG_USER_INETUTILS_RSHD)                += inetutils
dir_$(CONFIG_USER_SQLITE)                        += sqlite-3.2.6
dir_$(CONFIG_USER_LMBENCH)                       += lmbench3
dir_$(CONFIG_USER_BLACKFIN_STRACE)               += strace
dir_$(CONFIG_USER_BF561_COREBLD)                 += corebld
dir_$(CONFIG_USER_OPROFILE)                      += oprofile
dir_$(CONFIG_USER_FLTHDR)                        += flthdr
dir_$(CONFIG_USER_YAFFS_UTILS)                   += yaffs-utils
dir_$(CONFIG_USER_POUND)                         += pound
dir_$(CONFIG_USER_IRATTACH)                      += irattach
dir_$(CONFIG_USER_JPEGVIEW)                      += jpegview
dir_$(CONFIG_USER_BLACKFIN_WATCHDOGD)            += watchdogd
dir_$(CONFIG_USER_ALSA_UTILS)                    += alsa-utils
dir_$(CONFIG_USER_ZAPTEL)                        += zaptel
dir_$(CONFIG_USER_THREADSTACK)                   += threadstack-0.1
dir_$(CONFIG_USER_BLACKFIN_ASTERISK)             += asterisk
dir_$(CONFIG_USER_USBUTILS)                      += usbutils
dir_$(CONFIG_USER_BLUEZ)			 += bluez

all %::
	for i in $(dir_y) ; do make -C $$i $@ || exit $$? ; done
