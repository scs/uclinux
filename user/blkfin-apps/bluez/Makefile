dirs = bluez-libs-2.25 bluez-utils-2.25

all %::
	for i in $(dirs) ; do make -C $$i $@ || exit $$? ; done
