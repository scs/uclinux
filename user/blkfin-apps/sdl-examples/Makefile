DIRS=fire-1.0 plasma-1.0 xflame-1.0 warp-1.1 sdlroids-1.3.4 aliens-1.0.2 sdldoom-1.10 newvox-1.0 sierp-1.0 water-1.0

all: config.status
	for DIR in $(DIRS); \
	do \
		$(MAKE) -C $${DIR} ; \
	done

config.status:
	for DIR in $(DIRS) ; \
	do \
		find $${DIR} -type f -print0 | xargs -0 touch -r $${DIR}/configure ; \
		set -e ; \
		cd $${DIR} ; \
		if [ ! -f ./config.status ] ; then \
			./configure \
				--enable-cross-compile \
				--target=$(CONFIGURE_HOST) \
				--host=$(CONFIGURE_HOST) \
				--prefix=/usr \
				--with-sdl-prefix=$(PWD)/../staging/usr \
				--includedir=$(PWD)/../staging/usr/include ; \
		fi ; \
		cd ..; \
	done

clean:
	for DIR in $${DIRS} ; \
	do \
		-$(MAKE) -C $${DIR} distclean ;\
	done

romfs:
	$(ROMFSINST) -d aliens-1.0.2/aliens /usr/bin/aliens
	$(ROMFSINST) -d aliens-1.0.2/data /usr/bin/data
	$(ROMFSINST) -d fire-1.0/fire /usr/bin/fire
	$(ROMFSINST) -d plasma-1.0/plasma /usr/bin/plasma
	$(ROMFSINST) -d sdldoom-1.10/doom /usr/bin/doom
	$(ROMFSINST) -d doom1.wad /usr/bin/doom1.wad
	$(ROMFSINST) -d newvox-1.0/newvox /usr/bin/newvox
	$(ROMFSINST) -d sdlroids-1.3.4/sdlroids /usr/bin/sdlroids
	$(ROMFSINST) -d sdlroids-1.3.4/bmp /usr/bin/bmp
	$(ROMFSINST) -d sierp-1.0/sierp /usr/bin/sierp
	$(ROMFSINST) -d warp-1.1/warp /usr/bin/warp
	$(ROMFSINST) -d warp-1.1/leeloo.bmp /usr/bin/bmp/leeloo.bmp
	$(ROMFSINST) -d xflame-1.0/xflame /usr/bin/xflame

.PHONY: all clean romfs
