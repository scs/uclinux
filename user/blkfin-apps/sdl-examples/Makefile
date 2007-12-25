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

.PHONY: all clean romfs
