# To create your own version, just unpack mplayer tarball here
# and update the VER variable.  Or export your own from their
# svn via:
# svn export --ignore-externals -r <REV> svn://svn.mplayerhq.hu/mplayer/trunk MPlayer-svn-<REV>

VER = mplayer-svn-25211

# The version of ffmpeg *must* be relatively close in time to the
# version of mplayer since the build systems are so intertwined
#FFM = $(shell awk '$$1 == "VER" {print $$NF}' $(ROOTDIR)/lib/ffmpeg/Makefile)
FFM-mplayer-svn-25211 = ffmpeg-svn-11114
FFM = $(FFM-$(VER))

# Would be nice to use these, but configure/build system needs to stop sucking
#		--disable-lib{avutil,avcodec,avformat,postproc}_a 
#		--enable-lib{avutil,avcodec,avformat,postproc}_so
CONF_OPTS-y =
CONF_OPTS-m =
CONF_OPTS-$(CONFIG_LIB_LIBSDL_FORCE) += --enable-sdl --with-sdl-config=$(STAGEDIR)/usr/bin/sdl-config
CONF_OPTS-$(CONFIG_USER_LIRC) += --enable-lirc
CONF_OPTS-$(CONFIG_INPUT_JOYDEV) += --enable-joystick
CONF_OPTS-$(CONFIG_USER_MPLAYER_OSD) += --enable-menu

ifeq ($(FFM),)
FFM_LIB_DIRS = 
else
FFM_LIB_DIRS = libavutil libavcodec libavformat libpostproc libswscale
endif
FFM_LIB_DIRS := $(patsubst %,$(VER)/%,$(FFM_LIB_DIRS))

all: $(VER)/config.mak
	$(MAKE) -C $(VER)

$(FFM_LIB_DIRS):
	set -e ; \
	lib=$(notdir $@) ; \
	if [ ! -e $(VER)/$${lib} ] ; then \
		cp -pPR $(ROOTDIR)/lib/ffmpeg/$(FFM)/$${lib} $(VER)/$${lib}.tmp ; \
		find $(VER)/$${lib}.tmp -name .svn -print0 | xargs -0 rm -rf ; \
		mv $(VER)/$${lib}.tmp $(VER)/$${lib} ; \
	fi

ifeq ($(CONFIG_LIB_LIVE),y)
CONF_OPTS += --with-extraincdir=$(STAGEDIR)/usr/lib/live
else
CONF_OPTS += --disable-live
endif

$(VER)/config.mak: $(FFM_LIB_DIRS)
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	cd $(VER) ; \
	./configure \
		--enable-cross-compile \
		--target=$(CONFIGURE_HOST) \
		--host-cc=gcc \
		--cc=$(CONFIGURE_HOST)-gcc \
		--as=$(CONFIGURE_HOST)-as \
		--prefix=/usr \
		--confdir=/etc \
		--mandir=/usr/share/man \
		--enable-fbdev \
		--disable-mp3lib \
		$(CONF_OPTS) $(CONF_OPTS-y) $(CONF_OPTS-m)

clean:
	-$(MAKE) -C $(VER) distclean
	rm -rf $(FFM_LIB_DIRS)

romfs:
	$(ROMFSINST) -d $(VER)/mplayer /usr/bin/mplayer
	$(ROMFSINST) -d $(VER)/mencoder /usr/bin/mencoder
	$(ROMFSINST) -d $(VER)/etc/codecs.conf /etc/codecs.conf

.PHONY: all clean romfs
