#ifndef __DEVICES_H_
#define __DEVICES_H_

#include "sysdep/sysdep_display.h"

#ifdef __DEVICES_C_
#define EXTERN
#else
#define EXTERN extern
#endif

#define JOY_MAX			8
#define JOY_BUTTONS		32
#define JOY_AXES		16
#define JOY_DIRS		2
#define JOY_NAME_LEN		20
#define HISTORY_LENGTH		16
#define GUN_MAX			4

/* now axis entries in the mouse_list, these are get through another way,
   like the analog joy-values */
#define MOUSE_LIST_TOTAL_ENTRIES SYSDEP_DISPLAY_MOUSE_BUTTONS
#define MOUSE_LIST_LEN (MOUSE * MOUSE_LIST_TOTAL_ENTRIES)

enum
{
	JOY_NONE,
	JOY_STANDARD,
	JOY_PAD,
	JOY_USB,
	JOY_PS2,
	JOY_SDL
};

int xmame_keyboard_init(void);
void xmame_keyboard_exit();
void xmame_keyboard_register_event(struct sysdep_display_keyboard_event *event);
void xmame_keyboard_clear(void);

struct axisdata_struct
{
	/* current value */
	int val;
	/* calibration data */
	int min;
	int mid;
	int max;
	/* boolean values */
	int dirs[JOY_DIRS];
};

struct joydata_struct
{
	int fd;
	int num_axes;
	int num_buttons;
	struct axisdata_struct axis[JOY_AXES];
	int buttons[JOY_BUTTONS];
};

struct rapidfire_struct
{
	int setting[10];
	int status[10];
	int enable;
	int ctrl_button;
	int ctrl_prev_status;
};

EXTERN struct joydata_struct joy_data[JOY_MAX];
EXTERN struct rapidfire_struct rapidfire_data[4];
EXTERN void (*joy_poll_func)(void);
EXTERN int joytype;
EXTERN int is_usb_ps_gamepad;
EXTERN int rapidfire_enable;

extern struct rc_option joy_standard_opts[];
extern struct rc_option joy_pad_opts[];
extern struct rc_option joy_usb_opts[];
extern struct rc_option joy_ps2_opts[];

#ifdef USE_LIGHTGUN_ABS_EVENT
#include "joystick-drivers/lightgun_abs_event.h"
#endif

/*** prototypes ***/
void joy_evaluate_moves(void);
void joy_standard_init(void);
void joy_pad_init(void);
void joy_usb_init(void);
void joy_ps2_init(void);
void joy_ps2_exit(void);
void joy_SDL_init(void);
#undef EXTERN

#endif /* ifndef __DEVICES_H_ */
