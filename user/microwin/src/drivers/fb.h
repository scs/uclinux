/*
 * Copyright (c) 1999, 2000 Greg Haerr <greg@censoft.com>
 *
 * Framebuffer drivers header file for Microwindows Screen Drivers
 */

/* Linux framebuffer critical sections*/
#if VTSWITCH
extern volatile int mwdrawing;
#define DRAWON		++mwdrawing
#define DRAWOFF		--mwdrawing
#else
#define DRAWON
#define DRAWOFF
#endif

typedef unsigned char *		ADDR8;
typedef unsigned short *	ADDR16;
typedef unsigned long *		ADDR32;

/* subdriver entry points: one required for each draw function*/
typedef struct {
	int	 (*Init)(PSD psd);
	void 	 (*DrawPixel)(PSD psd, MWCOORD x, MWCOORD y, MWPIXELVAL c);
	MWPIXELVAL (*ReadPixel)(PSD psd, MWCOORD x, MWCOORD y);
	void 	 (*DrawHorzLine)(PSD psd, MWCOORD x1, MWCOORD x2, MWCOORD y,
			MWPIXELVAL c);
	void	 (*DrawVertLine)(PSD psd, MWCOORD x, MWCOORD y1, MWCOORD y2,
			MWPIXELVAL c);
	void	 (*FillRect)(PSD psd,MWCOORD x1,MWCOORD y1,MWCOORD x2,
			MWCOORD y2,MWPIXELVAL c);
	void	 (*Blit)(PSD destpsd, MWCOORD destx, MWCOORD desty, MWCOORD w,
			MWCOORD h,PSD srcpsd,MWCOORD srcx,MWCOORD srcy,long op);
	void	 (*DrawArea)(PSD psd, driver_gc_t *gc, int op);
} SUBDRIVER, *PSUBDRIVER;


/* global vars*/
extern int 	gr_mode;	/* temp kluge*/

/* entry points*/
/* scr_fb.c*/
void ioctl_getpalette(int start, int len, short *red, short *green,short *blue);
void ioctl_setpalette(int start, int len, short *red, short *green,short *blue);

/* genmem.c*/
void	gen_fillrect(PSD psd,MWCOORD x1,MWCOORD y1,MWCOORD x2,MWCOORD y2,
		MWPIXELVAL c);
MWBOOL	set_subdriver(PSD psd, PSUBDRIVER subdriver, MWBOOL init);
void	get_subdriver(PSD psd, PSUBDRIVER subdriver);

/* fb.c*/
PSUBDRIVER select_fb_subdriver(PSD psd);

/* fbportrait.c*/
extern PSUBDRIVER _subdriver;
extern SUBDRIVER  fbportrait;
