
ALL = dpmc_test active_to_fullon change_freq to_deepsleep to_sleep change_cclk change_sclk \
	fullon_to_active to_hibernate change_volt wdog

all:		$(ALL)

dpmc_test: dpmc_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ dpmc_test.c $(LDLIBS)

active_to_fullon: active_to_fullon.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ active_to_fullon.c $(LDLIBS) 

change_freq: change_freq.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ change_freq.c $(LDLIBS) 

to_deepsleep: to_deepsleep.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ to_deepsleep.c $(LDLIBS) 

to_sleep: to_sleep.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ to_sleep.c $(LDLIBS) 

change_cclk: change_cclk.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ change_cclk.c $(LDLIBS) 

change_sclk: change_sclk.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ change_sclk.c $(LDLIBS) 

fullon_to_active: fullon_to_active.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ fullon_to_active.c $(LDLIBS) 

to_hibernate: to_hibernate.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ to_hibernate.c $(LDLIBS) 

change_volt: change_volt.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ change_volt.c $(LDLIBS) 

wdog: wdog.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ wdog.c $(LDLIBS) 
romfs:
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_DPMC /bin/dpmc_test
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_DPMC /bin/active_to_fullon
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_DPMC /bin/change_freq
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_DPMC /bin/to_deepsleep
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_DPMC /bin/to_sleep
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_DPMC /bin/change_cclk
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_DPMC /bin/change_sclk
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_DPMC /bin/fullon_to_active
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_DPMC /bin/to_hibernate
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_DPMC /bin/change_volt
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_DPMC /bin/wdog

clean:
	rm -f *.elf *.gdb *.o dpmc_test active_to_fullon change_freq to_deepsleep to_sleep change_cclk change_sclk \
	fullon_to_active to_hibernate change_volt wdog
