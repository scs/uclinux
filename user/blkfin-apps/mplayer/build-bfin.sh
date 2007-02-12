#!/bin/bash 

#Description: Build MPlayer-1.0rc1 for Blackfin. Based on work by M.H. Fan <mhfan@hhcn.com> 

#Update History:
# 2007-02-08: Enable playing rtsp stream. 

ARCH=bfin
UCLINUX_PATH=/home/adam/workspace/multimedia/mplayer/uclinux-dist-0109

PREFIX=${PWD}/../install
LIBMAD_PATH=${UCLINUX_PATH}/lib/libmad/DESTDIR/usr

LIBLIVE_PATH=${PWD}/../live

TARGET=bfin-uclinux
CPU=bfin

OPTFLAGS="-O3 -mfdpic -mfast-fp -DNDEBUG=1"

#CPPFLAGS="-D__uClinux__ -DEMBED"

CFLAGS=""
CFLAGS="${CFLAGS} -I${LIBMAD_PATH}/include"

LDFLAGS="-s"
LDFLAGS="${LDFLAGS} -L${LIBMAD_PATH}/lib"
if echo $OPTFLAGS | grep -q mfdpic; then
	LDFLAGS="$LDFLAGS -mfdpic"; # XXX: -shared
else
	LDFLAGS="$LDFLAGS -static -Wl,-elf2flt";
fi

if [ ! -e ${UCLINUX_PATH} ]; then
	echo -e "Missing uClinux-dist directory path:\n\t${UCLINUX_PATH}"; sleep 1;
fi

if [ ! -e ${PREFIX} ]; then
    echo -e "Missing installation prefix: ${PREFIX}"; sleep 1;
fi


### XXX: you don't need to modify the following lines.
CROSS_COMPILE=${TARGET}-

export CPU ARCH TARGET CROSS_COMPILE

OPTFLAGS="-fomit-frame-pointer -ffast-math -fsigned-char ${OPTFLAGS}"
#OPTFLAGS="-ffast-math -fsigned-char ${OPTFLAGS}"

CFLAGS="-Wall -pipe ${OPTFLAGS} ${CFLAGS}"

CXXFLAGS="${CFLAGS}"

export CFLAGS LIBS LDFLAGS CXXFLAGS CXXLIBS

AS=${CROSS_COMPILE}as
LD=${CROSS_COMPILE}ld
CC=${CROSS_COMPILE}gcc
CPP=${CROSS_COMPILE}cpp
CXX=${CROSS_COMPILE}g++

export AS LD CC CXX CPP

HOSTCC=gcc
HOSTCXX=g++
HOST=i486-linux-gnu

export HOST HOSTCC HOSTCXX

# Configuration - we force to disable the auto-dectect configs

MP_INSTALL="--prefix=${PREFIX} "

MP_FEATURES="--enable-largefiles \
  --enable-live --with-livelibdir=${LIBLIVE_PATH} \
  --disable-mencoder \
  --disable-termcap \
  --disable-termios \
  --disable-iconv \
  --disable-langinfo \
  --disable-lirc \
  --disable-lircc \
  --disable-vm \
  --disable-xf86keysym \
  --disable-radio \
  --disable-radio-v4l2 \
  --disable-tv \
  --disable-tv-v4l1 \
  --disable-tv-v4l2 \
  --disable-tv-bsdbt848 \
  --disable-pvr \
  --disable-rtc \
  --disable-winsock2 \
  --disable-smb \
  --disable-dvdnav \
  --disable-dvdread \
  --disable-mpdvdkit \
  --disable-cdparanoia \
  --disable-bitmap-font \
  --disable-freetype \
  --disable-fontconfig \
  --disable-unrarlib \
  --disable-sortsub \
  --disable-fribidi \
  --disable-enca \
  --disable-macosx \
  --disable-maemo \
  --disable-macosx-bundle \
  --disable-inet6 \
  --disable-gethostbyname2 \
  --disable-ftp \
  --disable-vstream \
  --disable-pthreads \
  --disable-ass" 

MP_DECODERS="h264_decoder mpeg4_decoder wmav1_decoder wmav2_decoder flac_decoder mpeg1video_decoder msmpeg4v3_decoder wmv1_decoder"

MP_PARSERS="h264_parser mpeg4video_parser mpegvideo_parser"  

MP_CODECS="--enable-libavutil  \
  --enable-libavcodec \
  --enable-mad 
  --enable-faad-internal \
  --enable-faad-fixed \
  --disable-faad-external \
  --disable-gif \
  --disable-png \
  --disable-jpeg \
  --disable-libcdio \
  --disable-liblzo \
  --disable-win32 \
  --disable-qtx \
  --disable-xanim \
  --disable-real \
  --disable-xvid  \
  --disable-x264 \
  --disable-nut \
  --disable-libavformat \
  --disable-libpostproc \
  --disable-libavutil_so \
  --disable-libavcodec_so  \
  --disable-libavformat_so \
  --disable-libpostproc_so \
  --disable-libavcodec_mpegaudio_hp \
  --disable-libfame \
  --disable-tremor-internal \
  --disable-tremor-external \
  --disable-libvorbis \
  --disable-speex  \
  --disable-theora \
  --disable-faac \
  --disable-ladspa \
  --disable-libdv \
  --disable-toolame  \
  --disable-twolame \
  --disable-mp3lib \
  --disable-liba52 \
  --disable-libdts \
  --disable-libmpeg2 \
  --disable-musepack \
  --disable-amr_nb \
  --disable-amr_nb-fixed \
  --disable-amr_wb " 

MP_VOUTPUT="--disable-vidix-internal \
  --disable-vidix-external \
  --disable-gl \
  --disable-dga \
  --disable-vesa \
  --disable-svga \
  --disable-sdl   \
  --disable-aa  \
  --disable-caca \
  --disable-ggi  \
  --disable-ggiwmh \
  --disable-directx \
  --disable-dxr2 \
  --disable-dxr3  \
  --disable-ivtv \
  --disable-dvb  \
  --disable-dvbhead \
  --disable-mga  \
  --disable-xmga  \
  --disable-xv   \
  --disable-xvmc  \
  --disable-vm  \
  --disable-xinerama \
  --disable-x11  \
  --disable-xshape \
  --disable-directfb \
  --disable-zr \
  --disable-tga \
  --disable-pnm  \
  --disable-md5sum \
  --enable-fbdev"

MP_AOUTPUT="--enable-alsa \
  --enable-ossaudio \
  --disable-arts   \
  --disable-esd  \
  --disable-polyp \
  --disable-jack   \
  --disable-openal  \
  --disable-nas  \
  --disable-sgiaudio \
  --disable-sunaudio  \
  --disable-win32waveout \
  --enable-select" 

MP_MISC="--enable-cross-compile \
  --cc=${CC} \
  --host-cc=${HOSTCC} \
  --as=${AS} \
  --target=${ARCH} \
  --disable-static " 

MP_ADVANCED="--disable-mmx \
  --disable-mmxext \
  --disable-3dnow \
  --disable-3dnowext \
  --disable-sse   \
  --disable-sse2  \
  --disable-shm   \
  --disable-altivec \
  --disable-armv5te \
  --disable-iwmmxt \
  --disable-fastmemcpy \
  --disable-big-endian \
  --disable-debug \
  --disable-profile "  

make distclean;

./configure ${MP_MISC} ${MP_INSTALL} ${MP_FEATURES} ${MP_CODECS} ${MP_VOUTPUT} ${MP_AOUTPUT} ${MP_ADVANCED} --enable-decoder-only="${MP_DECODERS}" --enable-parser-only="${MP_PARSERS}"



# Ugly fix to further disable unnecessary configs
sed -i -e "s/\(CONFIG_.*_ENCODER=\).*/\1no/g" config.mak \
&& sed -i -e "s/\(CONFIG_.*_DEMUXER=\).*/\1no/g" config.mak \
&& sed -i -e "s/#define \(CONFIG_.*_ENCODER\).*/#undef \1/g" config.h \
&& sed -i -e "s/#define \(CONFIG_.*_DEMUXER\).*/#undef \1/g" config.h \
&& sed -i -e "s/#define CONFIG_ENCODERS 1/#undef CONFIG_ENCODERS/" config.h \
&& sed -i -e "s/#define CONFIG_DEMUXERS 1/#undef CONFIG_DEMUXERS/" config.h \
&& sed -i -e "s/\(#define MAX_OUTBURST\) .*/\1 16384/" config.h \
&& sed -i -e "s/#undef FAST_OSD_TABLE/#define FAST_OSD_TABLE 1/" config.h \
&& sed -i -e "s/#undef FAST_OSD/#define FAST_OSD 1/" config.h 

make
