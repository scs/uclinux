#ifndef __FXGEN_H
#define __FXGEN_H

#include "sysdep/sysdep_display.h"

int  InitGlide(void);
void ExitGlide(void);
int  InitParams(void);
int  InitVScreen(int reopen);
void CloseVScreen(void);
void VScreenCatchSignals(void);
void VScreenRestoreSignals(void);
const char * xfx_update_display(mame_bitmap *bitmap,
	  rectangle *vis_area,  rectangle *dirty_area,
	  struct sysdep_palette_struct *palette,
	  int flags);

extern unsigned int fxwidth;
extern unsigned int fxheight;
extern struct rc_option	fx_opts[];

#endif
