#include <string.h>
#include <vga.h>
#include <vgakeyboard.h>
/* fix ansi compilation */
#define inline
#include <vgamouse.h>
#undef inline
#include <signal.h>
#include <linux/kd.h>
#include <sys/ioctl.h>
#include <sys/vt.h>
#include "sysdep/sysdep_display_priv.h"

static int console_fd       = -1;
static int mouse_fd         = -1;
static int leds             =  0;
static int release_signal   = -1;
static int acquire_signal   = -1;
static struct sigaction release_sa;
static struct sigaction oldrelease_sa;
static struct sigaction acquire_sa;
static struct sigaction oldacquire_sa;
static void (*release_function)(void) = NULL;
static void (*acquire_function)(void) = NULL;
static int keyboard_sync_lost = 0;

static const char scancode_to_unicode[128][2] = {
	{ 0,   0   }, /* 0 */
	{ 0,   0   },
	{ '1', '!' },
	{ '2', '@' },
	{ '3', '#' },
	{ '4', '$' },
	{ '5', '%' },
	{ '6', '^' },
	{ '7', '&' },
	{ '8', '*' },
	{ '9', '(' }, /* 10 */
	{ '0', ')' },
	{ '-', '_' },
	{ '=', '+' },
	{ 0x8, 0x8 },
	{ 0,   0   },
	{ 'q', 'Q' },
	{ 'w', 'W' },
	{ 'e', 'E' },
	{ 'r', 'R' },
	{ 't', 'T' }, /* 20 */
	{ 'y', 'Y' },
	{ 'u', 'U' },
	{ 'i', 'I' },
	{ 'o', 'O' },
	{ 'p', 'P' },
	{ '[', '{' },
	{ ']', '}' },
	{ 0,   0   },
	{ 0,   0   },
	{ 'a', 'A' }, /* 30 */
	{ 's', 'S' },
	{ 'd', 'D' },
	{ 'f', 'F' },
	{ 'g', 'G' },
	{ 'h', 'H' },
	{ 'j', 'J' },
	{ 'k', 'K' },
	{ 'l', 'L' },
	{ ';', ':' },
	{ '\'', '"' },/* 40 */
	{ '`', '~' },
	{ 0,   0   },
	{ '\\', '|' },
	{ 'z', 'Z' },
	{ 'x', 'X' },
	{ 'c', 'C' },
	{ 'v', 'V' },
	{ 'b', 'B' },
	{ 'n', 'N' },
	{ 'm', 'M' }, /* 50 */
	{ ',', '<' },
	{ '.', '>' },
	{ '/', '?' },
	{ 0,   0   },
	{ '*', '*' },
	{ 0,   0   },
	{ ' ', ' ' },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   }, /* 60 */
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   }, /* 70 */
	{ '7', '7' },
	{ '8', '8' },
	{ '9', '9' },
	{ '-', '-' },
	{ '4', '4' },
	{ '5', '5' },
	{ '6', '6' },
	{ '+', '+' },
	{ '1', '1' },
	{ '2', '2' }, /* 80 */
	{ '3', '3' },
	{ '0', '0' },
	{ '.', '.' },
	{ 0,   0   },
	{ 0,   0   },
	{ '\\', '|' },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   }, /* 90 */
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ '/', '/' },
	{ 0,   0   },
	{ 0,   0   }, /* 100 */
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   }, /* 110 */
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   }, /* 120 */
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   },
	{ 0,   0   }
};

void release_handler(int n)
{
	if (release_function)
		release_function();
	oldrelease_sa.sa_handler(n);
	sigaction(release_signal, &release_sa, NULL);
	sigaction(acquire_signal, &acquire_sa, NULL);
}

void acquire_handler(int n)
{
	oldacquire_sa.sa_handler(n);
	sigaction(release_signal, &release_sa, NULL);
	sigaction(acquire_signal, &acquire_sa, NULL);
	keyboard_clearstate();
	keyboard_sync_lost = 1;
	if (console_fd >= 0)
		ioctl(console_fd, KDSETLED, leds);
	if (acquire_function)
		acquire_function();
}

void keyboard_handler(int scancode, int press)
{
	static int shift = 0;
	int shift_mask = 0;
	struct sysdep_display_keyboard_event event;

	switch (scancode)
	{
		case SCANCODE_LEFTSHIFT:
			shift_mask = 0x01;
			break;
		case SCANCODE_RIGHTSHIFT:
			shift_mask = 0x02;
			break;
	}

	if (press)
		shift |= shift_mask;
	else
		shift &= ~shift_mask;

	event.press = press;   
	event.scancode = scancode;
	event.unicode = scancode_to_unicode[scancode][shift? 1:0];
	sysdep_display_params.keyboard_handler(&event);
}

int svga_input_init(void)
{
	/* open the mouse here and not in open/close, this is not done
	   because this requires root rights, but because open/close can
	   be called multiple times, and svgalib's mouse_open/close can't
	   handle that */
	mouse_fd = mouse_init_return_fd("/dev/mouse", vga_getmousetype(),
			MOUSE_DEFAULTSAMPLERATE);
	if(mouse_fd < 0)
	{
		perror("mouse_init");
		fprintf(stderr, "SVGALib: failed to open mouse device\n");
	}
	
	return 0;
}

void svga_input_exit(void)
{
	if (mouse_fd >= 0)
		mouse_close();
}

int svga_input_open(void (*release_func)(void), void (*acquire_func)(void))
{
	extern int __svgalib_tty_fd;

	/* svgalib prior to 1.4.1 used SIGUSR1 and SIGUSR2 as signals for
	   console switching later versions use SIGPROF and SIGUNUSED, but
	   certain distros have changed svgalib 1.4.1 and later to return
	   to the old behaviour because of glibc conflicts.

	   Thus we can no longer use the svgalib version to determine which
	   signals are used. To solve this problem we query the tty to see
	   which signals are actually used. which we should have done in the
	   first place :) 
	   
	   To make it even more fun later svgalibs add a novccontrol option
	   to /etc/vga/libvga.conf which when set results in disabling
	   svgalibs vccontrol altogether this can be recognised by
	   __svgalib_tty_fd being -1, in this case we don't have any way to
	   know if vc's are changed (I dunno if they can be changed with this
	   option set), so we just do nothing if __svgalib_tty_fd == -1. 
	   
	   Last but not least svgalib >= 1.9.14 don't export __svgalib_tty_fd
	   from the .so anymore. Which gets us into the trouble we deserve
	   for using internal symbols. Strange enough this doesn't result
	   in a linker error but in __svgalib_tty_fd being -1. Luckily
	   svgalib >= 19.14 always uses SIGUSR1 and SIGUSR2, so this
	   can be worked around by detecting the svgalib version and
	   assuming SIGUSR1 and SIGUSR2 if its >= 1.9.14 . */
	if (vga_setmode(-1) >= 0x1914)
	{
		release_signal = SIGUSR1;
		acquire_signal = SIGUSR2;
	}
	else if(__svgalib_tty_fd != -1)
	{
		struct vt_mode vtmode;

		if(ioctl(__svgalib_tty_fd, VT_GETMODE, &vtmode) == -1)
		{
			fprintf(stderr, "Svgalib: Error: Couldn't get tty modeinfo (tty-fd = %d).\n", __svgalib_tty_fd);
			return -1;
		}
		release_signal = vtmode.relsig;
		acquire_signal = vtmode.acqsig;
	}
	else
		fprintf(stderr, "Svgalib: Warning: Couldn't catch console switch signals (tty-fd = %d).\n", __svgalib_tty_fd);

	if (release_signal != -1)
	{
		release_function = release_func;
		acquire_function = acquire_func;

		/* catch console switch signals to enable /
		   disable the vga pass through */
		memset(&release_sa, 0, sizeof(struct sigaction));
		memset(&acquire_sa, 0, sizeof(struct sigaction));
		release_sa.sa_handler = release_handler;
		acquire_sa.sa_handler = acquire_handler;
		sigaction(release_signal, &release_sa, &oldrelease_sa);
		sigaction(acquire_signal, &acquire_sa, &oldacquire_sa);
	}

	/* init the keyboard */
	if ((console_fd = keyboard_init_return_fd()) < 0)
	{
		fprintf(stderr, "Svgalib: Error: Couldn't open keyboard\n");
		return -1;
	}
	keyboard_seteventhandler(keyboard_handler);
	ioctl(console_fd, KDSETLED, leds);

	/* init the mouse */
	if(mouse_fd >= 0)
	{
		/* fix ranges and initial position of mouse */
		mouse_setrange_6d(-500,500, -500,500, -500,500, -500,500,
				-500,500, -500,500, MOUSE_6DIM);
		mouse_setposition_6d(0, 0, 0, 0, 0, 0, MOUSE_6DIM);
	}

	return 0;
}

void svga_input_close(void)
{
	/* restore the old handlers */
	if (release_signal != -1)
	{
		sigaction(release_signal, &oldrelease_sa, NULL);
		sigaction(acquire_signal, &oldacquire_sa, NULL);
	}

	if (console_fd >= 0)
	{
		ioctl(console_fd, KDSETLED, 8);
		keyboard_close();
	}
}

void sysdep_display_update_mouse (void)
{
	int i, mouse_buttons;

	if (mouse_fd < 0)
		return;

	mouse_update();

	mouse_getposition_6d(&sysdep_display_mouse_data[0].deltas[0],
			&sysdep_display_mouse_data[0].deltas[1],
			&sysdep_display_mouse_data[0].deltas[2],
			&sysdep_display_mouse_data[0].deltas[3],
			&sysdep_display_mouse_data[0].deltas[4],
			&sysdep_display_mouse_data[0].deltas[5]);

	/* scale down the delta's to some more sane values */
	for(i=0; i<6; i++)
		sysdep_display_mouse_data[0].deltas[i] /= 20;

	mouse_buttons = mouse_getbutton();

	for(i=0; i<SYSDEP_DISPLAY_MOUSE_BUTTONS; i++)
	{
		sysdep_display_mouse_data[0].buttons[i] = mouse_buttons & (0x01 << i);
	}

	mouse_setposition_6d(0, 0, 0, 0, 0, 0, MOUSE_6DIM);
}

void svga_input_set_keybleds(int new_leds)
{
	static int old_leds = 0;

	if (old_leds != new_leds)
	{
		leds = 0;

		if (new_leds & 0x01)
			leds |= LED_NUM;
		if (new_leds & 0x02)
			leds |= LED_CAP;
		if (new_leds & 0x04)
			leds |= LED_SCR;

		if (console_fd >= 0)
			ioctl(console_fd, KDSETLED, leds);

		old_leds = new_leds;
	}
}

int sysdep_display_driver_update_keyboard(void)
{
	keyboard_update();
	if (keyboard_sync_lost)
	{
		keyboard_sync_lost = 0;
		return SYSDEP_DISPLAY_KEYBOARD_SYNC_LOST;
	}
	return 0;
}
