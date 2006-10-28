all:
	@WORKDIR=`pwd`; \
	cd bluez-libs-2.25; \
	./configure CC=bfin-uclinux-gcc --prefix=$$WORKDIR/lib-output --host=bfin-linux --build=bfin --enable-shared=no --enable-static=yes; \
	make || exit; \
	make install || exit; \
	cd ../bluez-utils-2.25; \
	./configure CC=bfin-uclinux-gcc --host=bfin-linux --build=bfin --prefix=$$WORKDIR/bluez-output --with-bluez=$$WORKDIR/lib-output CFLAGS="-Wl,-elf2flt -static -DUCLINUX" CPPFLAGS="-I$$WORKDIR/lib-output/include"; \
	make || exit; \
	make install || exit; \
	cd ../;

clean:
	-make -C bluez-libs-2.25 clean
	-make -C bluez-utils-2.25 clean
	rm -rf lib-output
	rm -rf bluez-output

romfs:
	for bin in `cd bluez-output/bin ; ls` ; do \
		$(ROMFSINST) bluez-output/bin/$$bin /bin/$$bin || exit $$? ; \
	done ; \
	for sbin in `cd bluez-output/sbin ; ls` ; do \
		$(ROMFSINST) bluez-output/sbin/$$sbin /bin/$$sbin || exit $$? ; \
	done ; \
	mkdir -p $(ROMFSDIR)/etc/bluetooth ; \
	for etc in `cd bluez-output/etc/bluetooth ; ls` ; do \
		$(ROMFSINST) bluez-output/etc/bluetooth/$$etc /etc/bluetooth/$$etc || exit $$? ; \
	done

