#ifndef __EFFECT_H
#define __EFFECT_H

#include "sysdep/sysdep_display_priv.h"

/* buffer for doublebuffering */
extern char *effect_dbbuf;
extern char *rotate_dbbuf0;
extern char *rotate_dbbuf1;
extern char *rotate_dbbuf2;
extern char *_6tap2x_buf0;
extern char *_6tap2x_buf1;
extern char *_6tap2x_buf2;
extern char *_6tap2x_buf3;
extern char *_6tap2x_buf4;
extern char *_6tap2x_buf5;
extern void (*rotate_func)(void *dst, mame_bitmap *bitmap, int y, rectangle *bounds);
extern unsigned int effect_rgb2yuv[];

void blit_6tap_clear(int count);

#endif /* __EFFECT_H */
