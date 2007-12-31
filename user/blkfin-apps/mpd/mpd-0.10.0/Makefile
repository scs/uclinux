
.EXPORT_ALL_VARIABLES:

DIRS = src

all:
	for i in $(DIRS) ; do make -C $$i $@ || exit $?; done

clean:
	for i in $(DIRS) ; do make -C $$i clean ; done

romfs:
	echo "Installing MPD"
	make -C src romfs
