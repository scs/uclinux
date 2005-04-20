
dir_y =

all:
	for i in $(dir_y) ; do  make -C $$i || exit $? ; done

romfs:
	for i in $(dir_y) ; do  make -C $$i romfs || exit $? ; done

clean:
	-for i in $(dir_y) ; do \
		[ ! -d $$i ] || make -C $$i clean; \
	done


