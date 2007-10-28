/*     $Id: hw_mp3anywhere.h,v 5.1 2003/02/16 19:06:56 lirc Exp $     */

/****************************************************************************
 ** hw_mp3anywhere.h ********************************************************
 ****************************************************************************
 *
 * routines for X10 MP3 Anywhere receiver 
 * 
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 *	modified for logitech receiver by Isaac Lauer <inl101@alumni.psu.edu>
 *      modified for X10 receiver by Shawn Nycz <dscordia@eden.rutgers.edu>
 *
 */

#ifndef HW_MP3ANYWHERE_H
#define HW_MP3ANYWHERE_H

#include "drivers/lirc.h"

int mp3anywhere_decode(struct ir_remote *remote,
		  ir_code *prep,ir_code *codep,ir_code *postp,
		  int *repeat_flagp,lirc_t *remaining_gapp);
int mp3anywhere_init(void);
int mp3anywhere_deinit(void);
char *mp3anywhere_rec(struct ir_remote *remotes);

#endif
