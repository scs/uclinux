#include "xmame.h"
#include "devices.h"

static char *joy_dev = NULL; /* name of joystick device prefix */
static int use_old_driver = 0;

struct rc_option joy_standard_opts[] = {
   /* name, shortname, type, dest, deflt, min, max, func, help */
#if defined(__ARCH_netbsd) || defined(__ARCH_freebsd) || defined(__ARCH_openbsd)
   { "joydevname",	"jdev",			rc_string,	&joy_dev,
     "/dev/joy",	0,			0,		NULL,
     "Joystick device prefix (defaults to /dev/joy)" },
#elif defined __ARCH_linux || defined __ARCH_solaris
   { "joydevname",	"jdev",			rc_string,	&joy_dev,
     "/dev/js",		0,			0,		NULL,
     "Joystick device prefix (defaults to /dev/js)" },
#else
#ifdef STANDARD_JOYSTICK
#error You need to give a define for your OS here
#endif
#endif  /* arch */
   { NULL,		NULL,			rc_end,		NULL,
     NULL,		0,			0,		NULL,
     NULL }
};

#ifdef STANDARD_JOYSTICK

#include <sys/ioctl.h>

/* specific joystick for PC clones */
#if defined(__ARCH_netbsd) || defined(__ARCH_freebsd) || defined(__ARCH_openbsd)

#include <machine/joystick.h>
typedef struct joystick joy_struct;

#elif defined __ARCH_linux || defined __ARCH_solaris

#include <linux/joystick.h>
typedef struct JS_DATA_TYPE joy_struct;

#ifdef JS_VERSION
#define NEW_JOYSTICK 1
#endif

#else
#error "Standard joystick only supported under Linux, OpenBSD, NetBSD and FreeBSD. "
   "Patches to support other architectures are welcome."
#endif

/* #define JDEBUG */

void joy_standard_poll(void);
void joy_standard_new_poll(void);
static joy_struct my_joy_data;

static int first_dev = 0;
static int last_dev = JOY_MAX - 1;

void joy_standard_init(void)
{
	int i, j;
	int dev;
	char devname[50];
#ifdef NEW_JOYSTICK
	int version;
#endif

	/* 
	 * If the device name ends with an in-range digit, then don't 
	 * loop through all possible values below.  Just extract the 
	 * device number and use it.
	 */
	int pos = strlen(joy_dev) - 1;
	if (pos >= 0 && isdigit(joy_dev[pos]))
	{
		int devnum = joy_dev[pos] - '0';
		if (devnum < JOY_MAX)
		{
			first_dev = last_dev = devnum;
			joy_dev[pos] = 0;
		}
	}

	fprintf (stderr_file, "Standard joystick interface initialization...\n");
	for (i = 0, dev = first_dev; dev <= last_dev; i++, dev++)
	{
		snprintf(devname, sizeof(devname), "%s%d", joy_dev, dev);
		if ((joy_data[i].fd = open(devname, O_RDONLY)) >= 0)
		{
			if (use_old_driver)
			{
				if (read(joy_data[i].fd, &my_joy_data, sizeof(joy_struct)) != sizeof(joy_struct))
				{
					close(joy_data[i].fd);
					joy_data[i].fd = -1;
					continue;
				}
			}

			switch(use_old_driver)
			{
				case 0:
#ifdef NEW_JOYSTICK
					/* new joystick driver 1.x.x API 
					   check the running version of driver, if 1.x.x is
					   not detected fall back to 0.8 API */

					if (ioctl (joy_data[i].fd, JSIOCGVERSION, &version)==0)
					{
						char name[60];
						ioctl (joy_data[i].fd, JSIOCGAXES, &joy_data[i].num_axes);
						ioctl (joy_data[i].fd, JSIOCGBUTTONS, &joy_data[i].num_buttons);
						ioctl (joy_data[i].fd, JSIOCGNAME (sizeof (name)), name);
						if (joy_data[i].num_buttons > JOY_BUTTONS)
							joy_data[i].num_buttons = JOY_BUTTONS;
						if (joy_data[i].num_axes > JOY_AXES)
							joy_data[i].num_axes = JOY_AXES;
						fprintf (stderr_file, "Joystick: %s is %s\n", devname, name);
						fprintf (stderr_file, "Joystick: Built in driver version: %d.%d.%d\n", JS_VERSION >> 16, (JS_VERSION >> 8) & 0xff, JS_VERSION & 0xff);
						fprintf (stderr_file, "Joystick: Kernel driver version  : %d.%d.%d\n", version >> 16, (version >> 8) & 0xff, version & 0xff);
						for (j=0; j<joy_data[i].num_axes; j++)
						{
							joy_data[i].axis[j].min = -32768;
							joy_data[i].axis[j].max =  32768;
							joy_data[i].axis[j].mid = 0;
						}
						joy_poll_func = joy_standard_new_poll;
						break;
					}
					/* else we're running on a kernel with 0.8 driver */
					fprintf (stderr_file, "Joystick: %s unknown type\n", devname);
					fprintf (stderr_file, "Joystick: Built in driver version: %d.%d.%d\n", JS_VERSION >> 16, (JS_VERSION >> 8) & 0xff, JS_VERSION & 0xff);
					fprintf (stderr_file, "Joystick: Kernel driver version  : 0.8 ??\n");
					fprintf (stderr_file, "Joystick: Please update your Joystick driver !\n");
					fprintf (stderr_file, "Joystick: Using old interface method\n");
#else
					fprintf (stderr_file, "New joystick driver (1.x.x) support not compiled in.\n");
					fprintf (stderr_file, "Falling back to 0.8 joystick driver api\n");
#endif            
					use_old_driver = 1;
					/* fall through to the next case */
				case 1:
					joy_data[i].num_axes = 2;
#if defined(__ARCH_netbsd) || defined(__ARCH_freebsd) || defined(__ARCH_openbsd)
					joy_data[i].num_buttons = 2;
#else
					joy_data[i].num_buttons = JOY_BUTTONS;
#endif
					joy_data[i].axis[0].mid = my_joy_data.x;
					joy_data[i].axis[1].mid = my_joy_data.y;
					joy_data[i].axis[0].min = my_joy_data.x - 10;
					joy_data[i].axis[1].min = my_joy_data.y - 10;
					joy_data[i].axis[0].max = my_joy_data.x + 10;
					joy_data[i].axis[1].max = my_joy_data.y + 10;

					joy_poll_func = joy_standard_poll;
					break;
			}
			fcntl (joy_data[i].fd, F_SETFL, O_NONBLOCK);
		}
	}
}

#ifdef NEW_JOYSTICK
/* 
 * Routine to manage PC clones joystick via new Linux driver 1.2.xxx
 */
void joy_standard_new_poll (void)
{
	struct js_event js;
	int i;
	int dev;

	for (i = 0, dev = first_dev; dev <= last_dev; i++, dev++)
	{
		if (joy_data[i].fd < 0)
			continue;
		while ((read (joy_data[i].fd, &js, sizeof (struct js_event))) == sizeof (struct js_event))
		{
			switch (js.type & ~JS_EVENT_INIT)
			{
				case JS_EVENT_BUTTON:
					if (js.number < JOY_BUTTONS)
						joy_data[i].buttons[js.number] = js.value;
#ifdef JDEBUG
					fprintf (stderr, "Button=%d,value=%d\n", js.number, js.value);
#endif
					break;

				case JS_EVENT_AXIS:
					if (js.number < JOY_AXES)
						joy_data[i].axis[js.number].val = js.value;
#ifdef JDEBUG
					fprintf (stderr, "Axis=%d,value=%d\n", js.number, js.value);
#endif
					break;
			}
		}
	}
}
#endif

/* 
 * Routine to manage PC clones joystick via standard driver 
 */
void joy_standard_poll(void)
{
	int i, j;
	int dev;

	for (i = 0, dev = first_dev; dev <= last_dev; i++, dev++)
	{
		if (joy_data[i].fd < 0)
			continue;
		if (read (joy_data[i].fd, &my_joy_data, sizeof (joy_struct)) != sizeof (joy_struct))
			continue;

		/* get value of buttons */
#if defined(__ARCH_netbsd) || defined(__ARCH_freebsd) || defined(__ARCH_openbsd)
		joy_data[i].buttons[0] = my_joy_data.b1;
		joy_data[i].buttons[1] = my_joy_data.b2;
#else
		for (j = 0; j < JOY_BUTTONS; j++)
			joy_data[i].buttons[j] = my_joy_data.buttons & (0x01 << j);
#endif
		joy_data[i].axis[0].val = my_joy_data.x;
		joy_data[i].axis[1].val = my_joy_data.y;
	}
}

#endif
