dir_y =
dir_n =
dir_  =
dir_all = $(dir_y) $(dir_n) $(dir_)

dir_$(CONFIG_USER_BLACKFIN_DRV_PFBUTTONS)             += bf53x_pfbuttons


all romfs:
	for i in $(dir_y)   ; do $(MAKE) -C $$i $@ || exit $$? ; done

clean:
	for i in $(dir_all) ; do $(MAKE) -C $$i $@ || exit $$? ; done

.PHONY: all clean romfs
