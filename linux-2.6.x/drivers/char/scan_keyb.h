#ifndef	__DRIVER_CHAR_SCAN_KEYB_H
#define	__DRIVER_CHAR_SCAN_KEYB_H
/*
 *	$Id$
 *	Copyright (C) 2000 YAEGASHI Takeshi
 *	Generic scan keyboard driver
 */

int register_scan_keyboard(int (*scan)(unsigned char *buffer),
			   const unsigned char *table,
			   int length);

void __init scan_kbd_init(void);

#endif
