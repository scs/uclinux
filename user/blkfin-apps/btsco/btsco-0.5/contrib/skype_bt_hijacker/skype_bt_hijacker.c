/* skype_bt_hijacker 0.1 - keep open two sound devices, switch on demand
 *
 * Copyright (C) 2005 Andreas Beck <becka-btdvl@bedatec.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define HIJACKER_VERSION "0.1b"

#define _GNU_SOURCE

#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/soundcard.h>
/* #include <ansidecl.h> */

static void hijacker_init() __attribute__ ((constructor));

//the device Skype is opening by default (override with environment variable HIJACKDSP)
#define HIJACKDSP "/dev/dsp"

#define DEBUG(level, format, ...) \
	do { if (level<DEBUG_HIJACKER) fprintf (stderr, format, ## __VA_ARGS__); } while(0)

//debug
// 0 - no messages
// 1 - only error messages that probably explain failures (recommended)
// 2 - more output on opening/closing sound devices
// 3 - lots of messages on open/close actions
#define DEBUG_HIJACKER 1


//enable worakround bug in Skype 1.2.0.11 where Skype is trying to open dsp
//not closing it before (and failing thus)
#define WANT_DOUBLE_OPEN_FIX 1

//switchfile
#define DEFAULT_SWITCHFILE "/tmp/switch_dsp"
//secondary device to open alongside
#define DEFAULT_SECONDARY "/dev/dsp1"

//command to run via system() on opening of the audio device
#define ON_OPEN_RUNCOMMAND "skype_bt_hijacker_onopen"
#define ON_CLOSE_RUNCOMMAND "skype_bt_hijacker_onclose"

/* original C Library functions */
typedef int (*orig_open_ptr)(const char *pathname, int flags, ...);
typedef int (*orig_close_ptr)(int fd);
typedef int (*orig_write_ptr)(int fd, const void *buf, size_t count);
typedef int (*orig_ioctl_ptr)(int d, int request, void *argp);

static orig_open_ptr orig_open;
static orig_close_ptr orig_close;
static orig_write_ptr orig_write;
static orig_ioctl_ptr orig_ioctl;

static int origfd = -1, dsp_is_open = 0;
static char *secondary, *dsp, *switchfile;
static void rescue_old_libcalls(void);
static void filenames_init(void);
static void print_config(void);

static int swapped=0;

static struct {
	int openflags;
	int fragment, stereo, format, speed;
} soundconf = {
	O_RDWR,
	1024*1024,
	1,
	16,
	48000
};

// We do not need to actually play tricks on write. We swap the fds, thus
// really swapping files.
ssize_t write(int fd, const void *buf, size_t count)
{

	if(fd == origfd  &&  dsp_is_open){
		int hlp;
		hlp=!access(switchfile,F_OK);
		if (swapped!=hlp) {
			char *newdev;
			int newfd;
			
			/* check our swapping state. */
			swapped=hlp;
			newdev=swapped ? secondary : dsp;
			
			newfd=orig_open(newdev,soundconf.openflags);
			if (newfd==-1) {
				DEBUG(0,"hijacker: swap o/s failed!\n");
			} else {
				int parm;
				/* set it up - copy parms so they don't get changed in the worst case. */
				parm=soundconf.fragment;orig_ioctl(newfd, SNDCTL_DSP_SETFRAGMENT, &parm);
				if (parm!=soundconf.fragment) {
					DEBUG(0,"Can't set fragment. %d!=%d.\n",parm,soundconf.fragment);
				}
				parm=soundconf.stereo;  orig_ioctl(newfd, SNDCTL_DSP_SPEED,       &parm);
				if (parm!=soundconf.stereo) {
					DEBUG(0,"Can't set stereo. %d!=%d.\n",parm,soundconf.stereo);
				}
				parm=soundconf.format;  orig_ioctl(newfd, SNDCTL_DSP_SETFMT,      &parm);
				if (parm!=soundconf.format) {
					DEBUG(0,"Can't set format. %d!=%d.\n",parm,soundconf.format);
				}
				parm=soundconf.speed;   orig_ioctl(newfd, SNDCTL_DSP_SPEED,       &parm);
				if (parm!=soundconf.speed) {
					DEBUG(0,"Can't set speed. %d!=%d.\n",parm,soundconf.speed);
				}
				/* move it over */
				orig_close(origfd);
				dup2(newfd,origfd);
				orig_close(newfd);
				DEBUG(1,"hijacker: swap o/s\n");
			}
		}
	}

	return orig_write(fd, buf, count);
}

int ioctl (int d, int request, void *argp)
{
	DEBUG(2,"hijacker: ioctl called with fd %d\n", d);

	//clone ioctl of microphone to speakers as well
	if(d == origfd  &&  dsp_is_open){
		switch(request) {
			case SNDCTL_DSP_GETCAPS:
			case SNDCTL_DSP_GETISPACE:
			case SNDCTL_DSP_GETOSPACE:
			case SNDCTL_DSP_GETOPTR:
			case SNDCTL_DSP_GETIPTR:
			case SNDCTL_DSP_RESET:
			case SNDCTL_DSP_SYNC:
				break;
			case SNDCTL_DSP_SETFRAGMENT:
				soundconf.fragment=*((int *)argp);
				DEBUG(2,"hijacker: ioctl SETFRAGMEN %d\n", soundconf.fragment);
				break;
			case SNDCTL_DSP_STEREO:
				soundconf.stereo=*((int *)argp);
				DEBUG(2,"hijacker: ioctl STEREO %d\n", soundconf.stereo);
				break;
			case SNDCTL_DSP_SETFMT:
				soundconf.format=*((int *)argp);
				DEBUG(2,"hijacker: ioctl FORMAT %d\n", soundconf.format);
				break;
			case SNDCTL_DSP_SPEED:
				soundconf.speed=*((int *)argp);
				DEBUG(2,"hijacker: ioctl SPEED %d\n", soundconf.speed);
				break;
			default:
				DEBUG(0,"hijacker: unknown ioctl request %08x\n", request);
				break;
		}
		orig_ioctl(origfd, request, argp);
		return 0;
	}
	else
		return orig_ioctl(d, request, argp);
}

int close(int fd)
{
	DEBUG(2,"hijacker: close called with fd %d\n", fd);

	if (fd == origfd  &&  dsp_is_open){ 
		DEBUG(1,"hijacker: close called with orig fd %d\n", fd);
#ifdef ON_CLOSE_RUNCOMMAND
		system(ON_CLOSE_RUNCOMMAND);
#endif
		dsp_is_open = 0; 
		origfd = -1;
	} 

	return(orig_close(fd));
}

int open (const char *pathname, int flags, ...)
{
	int fd;
	va_list args;
	mode_t mode = 0;

	va_start(args,flags);
	if(flags & O_CREAT) {
		if (sizeof(int) >= sizeof(mode_t)) {
			mode = va_arg(args, int);
		} else {
			mode = va_arg(args, mode_t);
		}
	}
	va_end(args);

	/*
	 * If 'open' is trying to open the configured dsp device, it gets a new
	 * pathname of the chosen sound device. The same with the mixer
	 * device.
	 */
	if(strcmp(pathname, dsp) == 0){

#if (WANT_DOUBLE_OPEN_FIX)
		if(origfd!=-1){
			DEBUG(1,"hijacker: SKYPE 1.2.0.11 BUG WORKAROUND, open mic %s which wasn't closed. Closing it now.\n",dsp);
#ifdef ON_CLOSE_RUNCOMMAND
		system(ON_CLOSE_RUNCOMMAND);
#endif
			close(origfd);
		}
#endif

#ifdef ON_OPEN_RUNCOMMAND
		system(ON_OPEN_RUNCOMMAND);
#endif

		DEBUG(1,"hijacker: open DSP %s flags: %d\n",pathname, flags);

		{
			origfd = orig_open(dsp, flags, mode);
			swapped=0;	/* here, all is still well. */
			soundconf.openflags=flags;
			DEBUG(1,"hijacker: orig %s opened with fd %d\n", dsp, origfd);
		}

		dsp_is_open = 1;

		//return orig fd that will be later reference for bot origfd & secondaryfd
		return origfd;
	}

	/* call the original open command */
	fd=orig_open (pathname, flags, mode);

	DEBUG(1,"hijacker: open %s returned with fd %d\n", pathname, fd);

	return fd;
}

/* Save the original functions */

static void rescue_old_libcalls()
{
	orig_open = (orig_open_ptr)dlsym(RTLD_NEXT,"open");
	orig_close = (orig_close_ptr)dlsym(RTLD_NEXT,"close");
	orig_write = (orig_write_ptr)dlsym(RTLD_NEXT,"write");
	orig_ioctl = (orig_ioctl_ptr)dlsym(RTLD_NEXT,"ioctl");
}

static void filenames_init(){

	dsp=getenv("HIJACKDSP");
	if(!dsp) dsp=HIJACKDSP;

	secondary = getenv("SECONDARYDEV");
	if(!secondary) secondary = DEFAULT_SECONDARY;

	switchfile = getenv("SWITCHFILE");
	if(!switchfile) switchfile = DEFAULT_SWITCHFILE;
}

static void print_config(){
	DEBUG(1,"hijacker: when Skype opens DSP %s\n",dsp);
	DEBUG(1,"hijacker: secondary DSP used   %s\n",secondary);
	DEBUG(1,"hijacker: switchfile           %s\n",switchfile);
}

static void hijacker_init(void) {
	static int isinit=0;
	if (isinit) return;
	isinit++;
	DEBUG(1,"hijacker: skype_bt_hijacker v%s initializing.\n",HIJACKER_VERSION);
	rescue_old_libcalls();
	filenames_init();
	print_config();
}
