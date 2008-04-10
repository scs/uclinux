dir_y =
dir_n =
dir_  =

dir_$(CONFIG_BFIN537_LCV_IND) 			 += lcv-sht-cgi
dir_$(CONFIG_USER_BLACKFIN_PPIFCDCGI)            += ppifcd-cgi-lcv
dir_$(CONFIG_USER_IMGUPD_IMGUPD)		 += imgupd
dir_$(CONFIG_USER_BLACKFIN_LINPHONE)             += linphone
dir_$(CONFIG_USER_BLKFIN_APPS_DEVFBAPP_DEVTEST)  += devfbapp
dir_$(CONFIG_USER_BLKFIN_APPS_DEVVOUT_DEVOUT)    += devvoutapp
dir_$(CONFIG_USER_INETUTILS_RCP)                 += inetutils
dir_$(CONFIG_USER_INETUTILS_RSH)                 += inetutils
dir_$(CONFIG_USER_INETUTILS_RSHD)                += inetutils
dir_$(CONFIG_USER_SQLITE)                        += sqlite
dir_$(CONFIG_USER_LMBENCH)                       += lmbench3
dir_$(CONFIG_USER_BLACKFIN_STRACE)               += strace
dir_$(CONFIG_USER_BF561_COREBLD)                 += corebld
dir_$(CONFIG_USER_OPROFILE)                      += oprofile
dir_$(CONFIG_USER_YAFFS_UTILS)                   += yaffs-utils
dir_$(CONFIG_USER_POUND)                         += pound
dir_$(CONFIG_USER_IRATTACH)                      += irattach
dir_$(CONFIG_USER_JPEGVIEW)                      += jpegview
dir_$(CONFIG_USER_PNGVIEW)                       += pngview
dir_$(CONFIG_USER_BLACKFIN_WATCHDOGD)            += watchdogd
dir_$(CONFIG_USER_ALSA_UTILS)                    += alsa-utils
dir_$(CONFIG_USER_ZAPTEL)                        += zaptel
dir_$(CONFIG_USER_BLACKFIN_ASTERISK)             += asterisk
dir_$(CONFIG_USER_USBUTILS)                      += usbutils
dir_$(CONFIG_USER_BLUEZ)                         += bluez-utils
dir_$(CONFIG_USER_PICOCOM)                       += picocom
dir_$(CONFIG_USER_MPLAYER)                       += mplayer
dir_$(CONFIG_USER_VLC)                           += vlc
dir_$(CONFIG_USER_AWG)                           += ndso
dir_$(CONFIG_USER_NDSO)                          += ndso
dir_$(CONFIG_USER_NET_AUDIO)                     += net_audio
dir_$(CONFIG_USER_NET_AUDIO)                     += musicpd
dir_$(CONFIG_USER_MDMA_TESTS)                    += mdma
dir_$(CONFIG_USER_MDMA_KO)                       += mdma

all %::
	for i in $(dir_y) ; do $(MAKE) -C $$i $@ || exit $$? ; done

clean:
	for i in $(dir_y) $(dir_n) $(dir_) ; do $(MAKE) -C $$i $@ || exit $$? ; done
