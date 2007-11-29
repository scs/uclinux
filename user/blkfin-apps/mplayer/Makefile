# To create your own version, just unpack mplayer tarball here
# and update the VER variable.  Or export your own from their
# svn via:
# svn export --ignore-externals -r <REV> svn://svn.mplayerhq.hu/mplayer/trunk MPlayer-svn-<REV>

VER = MPlayer-svn-23293

# The version of ffmpeg *must* be relatively close in time to the
# version of mplayer since the build systems are so intertwined
#FFM = ffmpeg-svn-9768
FFM =

# Would be nice to use these, but configure/build system needs to stop sucking
#		--disable-lib{avutil,avcodec,avformat,postproc}_a 
#		--enable-lib{avutil,avcodec,avformat,postproc}_so
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
		--disable-mp3lib

clean:
	-$(MAKE) -C $(VER) distclean
	rm -rf $(FFM_LIB_DIRS)

romfs:
	$(ROMFSINST) -d $(VER)/mplayer /usr/bin/mplayer
	$(ROMFSINST) -d $(VER)/mencoder /usr/bin/mencoder
	$(ROMFSINST) -d $(VER)/etc/codecs.conf /etc/codecs.conf

.PHONY: all clean romfs
