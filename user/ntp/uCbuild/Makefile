
dir_y = libntp libparse
dir_n = 
dir_  = 

dir_$(CONFIG_USER_NTPD_NTPD)                += ntpd
dir_$(CONFIG_USER_NTPD_NTPDATE)             += ntpdate
dir_$(CONFIG_USER_NTPD_NTPQ)                += ntpdc

all:
	for i in $(dir_y); do \
		[ ! -d $$i ] || make -C $$i $@ || exit $$? ; \
	done

romfs:
	for i in $(dir_y); do \
		[ ! -d $$i ] || make -C $$i $@ || exit $$? ; \
	done

clean:
	for i in $(dir_y) $(dir_n) $(dir_); do \
		[ ! -d $$i ] || make -C $$i $@ || exit $$? ; \
	done

