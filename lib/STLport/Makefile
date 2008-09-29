#
# Makefile for building the std c++ library from STLport
# davidm@snapgear.com
#
# we need to override ARCH so the libs get a .a extention
#

all:
	make -C build/lib -f uclinux-dist.mak install ARCH=a

clean:
	make -C build/lib -f uclinux-dist.mak clean

romfs:
	$(ROMFSINST) -e CONFIG_LIB_STLPORT_SHARED \
		lib/libstdc++.so.5.0.0 /lib/libstdc++.so.5.0.0; \
	$(ROMFSINST) -e CONFIG_LIB_STLPORT_SHARED -s \
		libstdc++.so.5.0.0 /lib/libstdc++.so.5.0; \

