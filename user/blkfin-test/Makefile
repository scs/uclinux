dir_y = 
dir_n =
dir_  =
dir_all = $(dir_y) $(dir_n) $(dir_)

dir_$(CONFIG_USER_BLACKFIN_RTC)             += rtc-test
dir_$(CONFIG_USER_BLACKFIN_PFLAGS)          += pflags-test
dir_$(CONFIG_USER_BLACKFIN_PFBUTTONS)       += pfbuttons-test
dir_$(CONFIG_USER_BLACKFIN_PPIFCDTEST)      += ppifcd-test
dir_$(CONFIG_USER_BLACKFIN_DPMC)            += dpmc-test
dir_$(CONFIG_USER_BLACKFIN_DCPLB)           += dcplb-test
dir_$(CONFIG_USER_BLACKFIN_AUDIOTEST)       += audio_test
dir_$(CONFIG_USER_BLACKFIN_VIDEOTEST)       += video_test
dir_$(CONFIG_USER_BLACKFIN_TWI)             += twi_test
dir_$(CONFIG_USER_BLACKFIN_SPITEST)         += spi-test
dir_$(CONFIG_USER_BLACKFIN_TWILCDTEST)      += twi_lcd-test
dir_$(CONFIG_USER_BLACKFIN_TWIKEYPADTEST)   += twi_keypad-test
dir_$(CONFIG_USER_BLACKFIN_RTSCTSTEST)      += rtscts_test
dir_$(CONFIG_USER_SQLITE_TEST)              += sqlite_test
dir_$(CONFIG_USER_BLACKFIN_PPI)             += ppi-test
dir_$(CONFIG_USER_BLACKFIN_PTHREADTEST)     += pthread_test
dir_$(CONFIG_USER_BLACKFIN_PANICTEST)       += crash_test
dir_$(CONFIG_USER_BLACKFIN_TRAPSTEST)       += crash_test
dir_$(CONFIG_USER_NETPERF_TEST)             += netperf-bfin
dir_$(CONFIG_USER_SYSVIPC_TEST)             += sysv_ipc_test
dir_$(CONFIG_EVENT_TEST)                    += event_test
dir_$(CONFIG_AD5304_TEST)                   += ad5304_test
dir_$(CONFIG_AD9960_TEST)                   += ad9960_test
dir_$(CONFIG_FILE_OPERATION_TEST)           += file_operation-test
dir_$(CONFIG_USER_BLACKFIN_SPORT)           += sport_test
dir_$(CONFIG_USER_BLACKFIN_LATENCYTEST)     += latency-test
dir_$(CONFIG_USER_BLACKFIN_MALLOCPERF)      += malloc-perf
dir_$(CONFIG_USER_BLACKFIN_SRAMALLOC_TEST)  += sram-alloc-test
dir_$(CONFIG_USER_BLACKFIN_ERESTART_TEST)   += erestart_test
dir_$(CONFIG_CAMERA_TEST)                   += camera_test
dir_$(CONFIG_STRING_TEST)                   += string_test
dir_$(CONFIG_MMAP_TEST)                     += mmap_test
dir_$(CONFIG_SIMPLE_GPIO_TEST)              += simple-gpio-test

all romfs:
	for i in $(dir_y)   ; do $(MAKE) -C $$i $@ || exit $$? ; done

clean:
	for i in $(dir_all) ; do $(MAKE) -C $$i $@ || exit $$? ; done

.PHONY: all clean romfs
