This patch enables linphone-3.0.0 to use uclinux-dist/lib/libbfgdots/g729 library.


1. Apply linphone/g729_patch/linphone-3.0.0-g729.patch.
2. Create makefiles:
   # cd linphone-3.0.0/
   # ./autogen.sh
   Make sure your system installs automake-1.9.x or newer automake.
3. Configure uclinux to build libbfgdots and linphone
4. Build kernel and load 
5. Configure linphone to use g729 codec, e.g, in .linphonerc: 
   [audio_codec_4]
   mime=G729
   rate=8000
   enabled=1
