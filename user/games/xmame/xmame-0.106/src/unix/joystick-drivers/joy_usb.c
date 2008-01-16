/*
 * X-Mame USB HID joystick driver for NetBSD.
 *
 * Written by Krister Walfridsson <cato@df.lth.se>
 * Improved by Dieter Baron <dillo@giga.or.at>
 */
#include "xmame.h"
#include "devices.h"

static int calibrate=0;

struct rc_option joy_usb_opts[] = {
   /* name, shortname, type, dest, deflt, min, max, func, help */
   { "joyusb-calibrate", NULL,                  rc_bool,        &calibrate,
     "0",               0,                      0,              NULL,
     "Manually calibrate USB joysticks" },
   { NULL,		NULL,			rc_end,		NULL,
     NULL,		0,			0,		NULL,
     NULL }
};

#ifdef USB_JOYSTICK

    
#if !defined(__ARCH_openbsd) && !defined(__ARCH_netbsd) && !defined(__ARCH_freebsd)
#error "USB joysticks are only supported under OpenBSD, NetBSD and FreeBSD.  Patches to support other archs are welcome ;)"
#endif

#if defined(HAVE_USBHID_H) || defined(HAVE_LIBUSBHID_H)
#	ifdef HAVE_USBHID_H
#		include <usbhid.h>
#	endif
#	ifdef HAVE_LIBUSBHID_H
#		include <libusbhid.h>
#	endif
#else
#	ifdef __ARCH_netbsd
#		include <usb.h>
#	endif
#	ifdef __ARCH_freebsd
#		include <libusb.h>
#	endif
#endif

#ifdef __ARCH_freebsd
#include <osreldate.h>
#include <sys/ioctl.h>
#endif

#include <dev/usb/usb.h>
#include <dev/usb/usbhid.h>

int axis_usage[] = {
  HUG_X, HUG_Y, HUG_Z,
  HUG_RX, HUG_RY, HUG_RZ,
  HUG_SLIDER,
};

int axis_max = sizeof(axis_usage)/sizeof(axis_usage[0]);

struct priv_joydata_struct
{
  int dlen;
  int offset;
  char *data_buf;
  struct hid_item *axis_item[JOY_AXES];
  struct hid_item *button_item[JOY_BUTTONS];
  struct hid_item *hat_item;
  int hat_axis;
} priv_joy_data[JOY_MAX];

static struct hid_item *itemdup(struct hid_item *s);
static int joy_initialize_hid(int i);
static void joy_usb_poll(void);
static int joy_read(int fd, int i);



void joy_usb_init(void)
{
  int i;
  char devname[20];

  fprintf(stderr_file, "USB joystick interface initialization...\n");

  for (i = 0; i < JOY_MAX; i++)
    {
      sprintf(devname, "/dev/uhid%d", i);
      if ((joy_data[i].fd = open(devname, O_RDONLY | O_NONBLOCK)) != -1)
	{
	  if (!joy_initialize_hid(i))
	    {
	      close(joy_data[i].fd);
	      joy_data[i].fd = -1;
	    }
	}
    }

  joy_poll_func = joy_usb_poll;
}



static int joy_initialize_hid(int i)
{
  int size, is_joystick, report_id = 0;
  struct hid_data *d;
  struct hid_item h;
  struct hid_item *axis_item[axis_max];
  report_desc_t rd;
  int got_something;
  int j, n;

  if ((rd = hid_get_report_desc(joy_data[i].fd)) == 0)
    {
      fprintf(stderr_file, "error: /dev/uhid%d: %s", i, strerror(errno));
      return FALSE;
    }

#if defined(HAVE_USBHID_H) || defined(HAVE_LIBUSBHID_H)
#if defined(__ARCH_openbsd) || defined(__ARCH_netbsd) || (defined(__ARCH_freebsd) && __FreeBSD_version > 500000)
  if (ioctl(joy_data[i].fd, USB_GET_REPORT_ID, &report_id) < 0)
    {
      fprintf(stderr_file, "error: /dev/uhid%d: %s", i, strerror(errno));
      return FALSE;
    }
#endif

  size = hid_report_size(rd, hid_input, report_id);
  priv_joy_data[i].offset = 0;
#else
  size = hid_report_size(rd, hid_input, &report_id);
  priv_joy_data[i].offset = (report_id != 0);
#endif
  if ((priv_joy_data[i].data_buf = malloc(size)) == NULL)
    {
      fprintf(stderr_file, "error: couldn't malloc %d bytes\n", size);
      hid_dispose_report_desc(rd);
      return FALSE;
    }
  priv_joy_data[i].dlen = size;

  for (j=0; j<axis_max; j++)
    axis_item[j] = NULL;
  priv_joy_data[i].hat_item = NULL;
  for (j=0; j<JOY_AXES; j++)
    priv_joy_data[i].axis_item[j] = NULL;
  for (j=0; j<JOY_BUTTONS; j++)
    priv_joy_data[i].button_item[j] = NULL;

  is_joystick = 0;
  got_something = 0;
#if defined(HAVE_USBHID_H)
  for (d = hid_start_parse(rd, 1 << hid_input, report_id);
       hid_get_item(d, &h); )
#else
  for (d = hid_start_parse(rd, 1 << hid_input); hid_get_item(d, &h); )
#endif
    {
      int axis, usage, page;

      page = HID_PAGE(h.usage);
      usage = HID_USAGE(h.usage);

      /* This test is somewhat too simplistic, but this is how MicroSoft
       * does, so I guess it works for all joysticks/game pads. */
      is_joystick = is_joystick ||
	(h.kind == hid_collection &&
	 page == HUP_GENERIC_DESKTOP &&
	 (usage == HUG_JOYSTICK || usage == HUG_GAME_PAD));

      if (h.kind != hid_input)
	continue;

      if (!is_joystick)
	continue;

      if (page == HUP_GENERIC_DESKTOP)
	{
	  if (usage == HUG_HAT_SWITCH)
	    {
	      got_something = 1;
	      if (priv_joy_data[i].hat_item == NULL)
		priv_joy_data[i].hat_item = itemdup(&h);
	    }
	  else
	    {
	      for (j=0; j<axis_max; j++)
		if (usage == axis_usage[j])
		  {
		    got_something = 1;
		    if (axis_item[j] == NULL)
		      axis_item[j] = itemdup(&h);
		    break;
		  }
	    }
	}
      else if (page == HUP_BUTTON)
	{
	  if ((usage > 0) && (usage <= JOY_BUTTONS))
	    {
	      got_something = 1;
	      if (priv_joy_data[i].button_item[usage-1] == NULL)
		priv_joy_data[i].button_item[usage-1] = itemdup(&h);
	      if (usage > joy_data[i].num_buttons)
		joy_data[i].num_buttons = usage;
	    }
	}
    }
  hid_end_parse(d);

  if (!got_something)
    {
      free(priv_joy_data[i].data_buf);
      return 0;
    }

      
  for (j=0; j<axis_max; j++)
    {
      if (axis_item[j])
        {
	  n = joy_data[i].num_axes++;
	  priv_joy_data[i].axis_item[n] = axis_item[j];
	  
	  joy_data[i].axis[n].min
	    = priv_joy_data[i].axis_item[n]->logical_minimum;
	  joy_data[i].axis[n].max
	    = priv_joy_data[i].axis_item[n]->logical_maximum;
	  joy_data[i].axis[n].mid
	    = ((joy_data[i].axis[n].max-joy_data[i].axis[n].min+1)/2
	       + joy_data[i].axis[n].min);
	  joy_data[i].axis[n].val = joy_data[i].axis[n].mid;
	}
    }
      
  if (priv_joy_data[i].hat_item)
    {
      if (joy_data[i].num_axes < JOY_AXES-2)
        {
	  n = joy_data[i].num_axes;
	  joy_data[i].num_axes += 2;
	  priv_joy_data[i].hat_axis = n;
	  for (j=0; j<2; j++)
	    {
	      joy_data[i].axis[n+j].min = -1;
	      joy_data[i].axis[n+j].max = 1;
	      joy_data[i].axis[n+j].mid = 0;
	      joy_data[i].axis[n+j].val = 0;
	    }
	}
      else
        {
	  /* too many axes to support hat */
	  free(priv_joy_data[i].hat_item);
	  priv_joy_data[i].hat_item = NULL;
	}
    }

  if (calibrate)
    {
      int got_values;
      
      /*
	The values returned in the HID report may be wrong.  However,
	it works for most joysticks and krister's method requires
	moving the joystick about when starting xmame to calibrate,
	which is annoying.
	
	For such joysticks, calibration can be enabled with the
	-joyusb-calibrate command line option.

	We'll approximate the midpoint with the current joystick value
	if that can be read (some HID devices returns no data if the
	state has not changed since the last time it was read.)
      */
	  
      got_values = joy_read(joy_data[i].fd, i);
      
      for (j=0; j<joy_data[i].num_axes; j++)
        {
	  if (priv_joy_data[i].axis_item[j] == NULL)
	    {
	      /* HAT item doesn't need calibration */
	      continue;
	    }

	  if (got_values)
	    joy_data[i].axis[j].mid = joy_data[i].axis[j].val;
	  
	  /*
	    Approximate min/max values. Observe that we cannot use the
	    max/min values that the HID reports, since that is
	    theoretical values that may be wrong for analogs joystics
	    (especially if you have a joystick -> USB adaptor.) We
	    cannot use greater delta values than +/- 1, since it is OK
	    for a gamepad (or my USB TAC 2) to reports directions as
	    mid +/- 1.
	  */
	  
	  joy_data[i].axis[j].min = joy_data[i].axis[j].mid - 1;
	  joy_data[i].axis[j].max = joy_data[i].axis[j].mid + 1;
	}
    }
	  
  return 1;
}



static void joy_usb_poll(void)
{
  int i;

  for (i = 0; i < JOY_MAX; i++)
    {
      if (joy_data[i].fd >= 0)
	joy_read(joy_data[i].fd, i);
    }
}



static int joy_read(int fd, int i)
{
  /* 0   1   2   3   4   5   6   7 */
  /* u  ru  r   rd   d  ld  l   lu */
  const int hat_x[] = {
     0,  1,  1,  1,  0, -1, -1, -1
  };
  const int hat_y[] = {
    -1, -1,  0,  1,  1,  1,  0, -1
  };

  int len, new, d, j;
  char *p;

  new = 0;
  while ((len=read(fd, priv_joy_data[i].data_buf, priv_joy_data[i].dlen))
	 == priv_joy_data[i].dlen)
      new = 1;
  if (!new)
    return FALSE;

  p = priv_joy_data[i].data_buf + priv_joy_data[i].offset;

  for (j=0; j<joy_data[i].num_axes; j++)
    {
      if (priv_joy_data[i].axis_item[j])
	joy_data[i].axis[j].val=hid_get_data(p, priv_joy_data[i].axis_item[j]);
    }

  if (priv_joy_data[i].hat_item != NULL)
    {
      d = hid_get_data(p, priv_joy_data[i].hat_item)
	- priv_joy_data[i].hat_item->logical_minimum;
      j = priv_joy_data[i].hat_axis;
      if (d < 0 || d >= 8)
        {
	  joy_data[i].axis[j].val = 0;
	  joy_data[i].axis[j+1].val = 0;
	}
      else
        {
	  joy_data[i].axis[j].val = hat_x[d];
	  joy_data[i].axis[j+1].val = hat_y[d];
	}
    }

  for (j=0; j<joy_data[i].num_buttons; j++)
    {
      if (priv_joy_data[i].button_item[j])
	joy_data[i].buttons[j]
	  = (hid_get_data(p, priv_joy_data[i].button_item[j])
	     == priv_joy_data[i].button_item[j]->logical_maximum);
    }

  return TRUE;
}

static struct hid_item *itemdup(struct hid_item *s)
{
  struct hid_item *t;

  t = malloc(sizeof(*t));
  if (t == NULL)
    {
      fprintf(stderr_file, "error: Not enough memory for joystick. "
	      "Your joystick may fail to work correctly.\n");
      return NULL;
    }

  memcpy(t, s, sizeof(*t));

  return t;
}

#endif
