# Makefile for building the std c++ library from STLport

all:
	make -f uclinux-dist.mak -C src

clean:
	make -f uclinux-dist.mak -C src clean

romfs:
	echo $(ROMFSINST)
	$(ROMFSINST) -e CONFIG_LIB_STLPORT_SHARED \
		lib/libstdc++.so.4.6 /lib/libstdc++.so.4.6; \
	$(ROMFSINST) -e CONFIG_LIB_STLPORT_SHARED -s \
		/lib/libstdc++.so.4.6 /lib/libstdc++.so; \

