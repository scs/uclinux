dir_y = linux-uvc-svn-220 luvcview-svn-14
dir_n =
dir_  =
dir_all = $(dir_y) $(dir_n) $(dir_)

all romfs:
	for i in $(dir_y)   ; do $(MAKE) -C $$i $@ || exit $$? ; done

clean:
	for i in $(dir_all) ; do $(MAKE) -C $$i $@ || exit $$? ; done

.PHONY: all clean romfs
