/*
 ******************* X-Mame header file *********************
 * file "xmame.h"
 *
 * by jantonio@dit.upm.es
 *
 ************************************************************
*/

#ifndef __XMAME_H_
#define __XMAME_H_

#ifdef __MAIN_C_
#define EXTERN
#else
#define EXTERN extern
#endif

/*
 * Include files.
 */

#ifdef openstep
#include <libc.h>
#include <math.h>
#endif /* openstep */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "osdepend.h"
#include "driver.h"
#include "mame.h"
#include "sysdep/rc.h"
#include "sysdep/sysdep_sound_stream.h"

/*
 * Definitions.
 */
 
#define OSD_OK			(0)
#define OSD_NOT_OK		(1)

#define DEBUG(x)

#define FRAMESKIP_LEVELS 12

/*
 * Global variables.
 */

/* Used for the rc handling. */
EXTERN struct rc_struct *rc;

EXTERN int		doublebuffer; /* xgl */

/* global variables and miscellaneous flags */

EXTERN float		video_fps;
EXTERN char		*home_dir;
EXTERN char		title[50];
EXTERN int		throttle;
EXTERN int		autoframeskip;
EXTERN int		frameskip;
EXTERN int		game_index;
EXTERN int 		sleep_idle;
EXTERN int 		max_autoframeskip;
EXTERN struct sysdep_sound_stream_struct *sysdep_sound_stream;
#ifdef MESS
extern char		crcdir[];
#endif

/* File descripters for stdout / stderr redirection, without svgalib inter
   fering */
extern FILE *stdout_file;
extern FILE *stderr_file;

/* input related */
int  osd_input_initpre(void);
int  osd_input_initpost(void);
void osd_input_close(void);
void osd_poll_joysticks(void);

/* Directory functions that used to be in the rc files. */
int check_and_create_dir(const char *name);
char *get_home_dir(void);
char *osd_dirname(const char *filename);

/* network funtions */
int  osd_net_init(void);
void osd_net_close(void);

/* debug functions */
int  osd_debug_init(void);
void osd_debug_close(void);

/* frameskip functions */
int dos_skip_next_frame();
int dos_show_fps(char *buffer);
int barath_skip_next_frame();
int barath_show_fps(char *buffer);

/* miscellaneous */
int xmame_config_init(int argc, char *argv[]);
void xmame_config_exit(void);
int frontend_list(const char *gamename);
int frontend_ident(const char *gamename);
void init_search_paths(void);
void init_rom_path(char *path);
void free_pathlists(void);
int should_sleep_idle();
void sound_update_refresh_rate(float newrate);
#ifndef HAVE_SNPRINTF
int snprintf(char *s, size_t maxlen, const char *fmt, ...);
#endif

/* option structs */
extern struct rc_option video_opts[];
extern struct rc_option sound_opts[];
extern struct rc_option input_opts[];
extern struct rc_option network_opts[];
extern struct rc_option fileio_opts[];
extern struct rc_option frontend_list_opts[];
extern struct rc_option frontend_ident_opts[];

#undef EXTERN
#endif
