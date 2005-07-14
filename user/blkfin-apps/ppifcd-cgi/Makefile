
dir_y =
dir_y += thttpd
dir_y += src


all:
	for i in $(dir_y) ; do  make -C $$i || exit $? ; done

romfs:
	for i in $(dir_y) ; do  make -C $$i romfs || exit $? ; done
	cp -Rf ./web/* $(ROMFSDIR)/
	chmod 666 $(ROMFSDIR)/*.htm

clean:
	-for i in $(dir_y) ; do \
		[ ! -d $$i ] || make -C $$i clean; \
	done


