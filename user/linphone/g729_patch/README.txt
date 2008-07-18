This patch enables linphone-2.0.1 to use uclinux-dist/lib/libbfgdots/g729 library.


1. Apply linphone/g729_patch/linphone-2.0.1-g729.patch.
2. Create makefiles:
   # cd linphone-2.0.1/mediastream2
   # ./autogen.sh
   Make sure your system installs automake-1.9.x
3. Configure uclinux to build libbfgdots and linphone
4. Build kernel and load 
5. Configure linphone to use g729 codec, e.g, in .linphonerc: 
   [audio_codec_4]
   mime=G729
   rate=8000
   enabled=1
