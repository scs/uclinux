dir_y =
dir_n =
dir_  =

dir_$(CONFIG_USER_IRDA_TOOLS) += irattach irdaping

all:
	for i in $(dir_y) ; do $(MAKE) -C $$i || exit $$? ; done

romfs:
	for i in $(dir_y) ; do $(MAKE) -C $$i $@ || exit $$? ; done

clean:
	for i in $(dir_y) $(dir_n) $(dir_) ; do $(MAKE) -C $$i $@ || exit $$? ; done
