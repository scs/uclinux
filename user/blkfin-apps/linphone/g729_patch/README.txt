This patch enables linphone to use uclinux-dist/lib/libbfgdots/g729 library.

1. Apply linphone/g729_patch/linphone-1.6.0-g729.patch.
2. Create makefiles:
   # cd linphone-1.6.0/mediastream2
   # ./autogen.sh
   Make sure your system installs automake-1.9.x
3. Apply linphone/g729_patch/mediastream_configure.patch
4. Configure uclinux to build libbfgdots and linphone
5. Build kernel and load 
6. Configure linphone to use g729 codec, e.g, in .linphonerc: 
   [audio_codec_4]
   mime=G729
   rate=8000
   enabled=1
