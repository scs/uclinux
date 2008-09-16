
check out the libsbc project from cvs and build and install it:

 cvs -d:pserver:anonymous@sbc.cvs.sourceforge.net:/cvsroot/sbc login
 cvs -z3 -d:pserver:anonymous@sbc.cvs.sourceforge.net:/cvsroot/sbc co -P sbc
 cd sbc
 ./bootstrap && ./configure --prefix=/usr && make all && sudo make install

in the toplevel of this project, run:

 ./bootstrap && ./configure --enable-fixed --enable-alsaplugin --prefix=/usr && make clean all && sudo make install

You should put something like this in your ~/.asoundrc with the 
headset address specified correctly:

	pcm.headphone {
	        type a2dp
	        bdaddr "00:08:F4:30:05:BB"
	}

You invoke the plugin with something like:

	aplay -B 1000000 -D pcm.headphone file.wav

You can also set a program like xmms to play to the alsa device "pcm.headphone"
Note that this device will not automatically appear in the list of alsa devices.
The alsa folks did this by design but they added a new api for clients to 
enumerate plugin devices.
