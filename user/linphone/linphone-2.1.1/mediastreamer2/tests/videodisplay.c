/*
mediastreamer2 library - modular sound and video processing and streaming
Copyright (C) 2006  Simon MORLAT (simon.morlat@linphone.org)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#include "mediastreamer2/mediastream.h"

int main(int argc, char *argv[]){
	VideoStream *vs;
	const char *devname="/dev/video0";
	int i;
	ms_init();

	/* this is to test the sequence start/stop */
	for(i=0;i<1;++i){
		int n;
		vs=video_preview_start(devname);

        	for(n=0;n<1000;++n){
#ifdef WIN32
        		Sleep(100);
			MSG msg;
			while (PeekMessage(&msg, NULL, 0, 0,1)){
        			TranslateMessage(&msg);
        			DispatchMessage(&msg);
			}
#else
			struct timespec ts;
			ts.tv_sec=0;
			ts.tv_nsec=10000000;
			nanosleep(&ts,NULL);

			if (vs) video_stream_iterate(vs);
#endif
		}
		video_preview_stop(vs);
	}
	return 0;
}
