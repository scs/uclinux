/*
 * Copyright (c) 1999, 2000 Greg Haerr <greg@censoft.com>
 * Portions Copyright (c) 1991 David I. Bell
 * Permission is granted to use, distribute, or modify this source,
 * provided that this copyright notice remains intact.
 *
 * Device-independent mid level screen device init routines
 *
 * These routines implement the smallest Microwindows engine level
 * interface to the screen driver.  By setting the NOFONTSORCLIPPING
 * config option, only these routines will be included, which can
 * be used to generate a low-level interface to the screen drivers
 * without dragging in any other GdXXX routines.
 */
#include <stdio.h>
#include <stdlib.h>
#include "device.h"

#if MSDOS | ELKS
#define NOSTDPAL8
#endif

/*
 * The following define can change depending on the window manager
 * usage of colors and layout of the 8bpp palette devpal8.c.
 * Color entries below this value won't be overwritten by user
 * programs or bitmap display conversion tables.
 */
#define FIRSTUSERPALENTRY	24  /* first writable pal entry over 16 color*/

       MWPIXELVAL gr_foreground;      /* current foreground color */
       MWPIXELVAL gr_background;      /* current background color */
       MWBOOL 	gr_usebg;    	    /* TRUE if background drawn in pixmaps */
       int 	gr_mode = MWMODE_SET; 	    /* drawing mode */
static MWSCREENINFO gr_sinfo;	    /* screen info for local routines*/
/*static*/ MWPALENTRY	gr_palette[256];    /* current palette*/
/*static*/ int	gr_firstuserpalentry;/* first user-changable palette entry*/
/*static*/ int 	gr_nextpalentry;    /* next available palette entry*/
	int	gr_portraitmode;    /* =1 for portrait mode*/

/*
 * Open low level graphics driver
 */
PSD
GdOpenScreen(void)
{
	PSD			psd;
	MWPALENTRY *		stdpal;

	psd = scrdev.Open(&scrdev);
	if (!psd)
		return NULL;
	GdGetScreenInfo(psd, &gr_sinfo);

	/* assume no user changable palette entries*/
	gr_firstuserpalentry = (int)psd->ncolors;

	/* set palette according to system colors and devpalX.c*/
	switch((int)psd->ncolors) {

#if !defined(NOSTDPAL1) /* don't require stdpal1 if not needed */
	case 2:		/* 1bpp*/
	{
		extern MWPALENTRY	mwstdpal1[2];
		stdpal = mwstdpal1;
	}
	break;
#endif

#if !defined(NOSTDPAL2) /* don't require stdpal2 if not needed */
	case 4:		/* 2bpp*/
	{
		extern MWPALENTRY	mwstdpal2[4];
		stdpal = mwstdpal2;
	}
	break;
#endif

#if !defined(NOSTDPAL4)
	/* don't require stdpal4 if not needed */
	case 8:		/* 3bpp - not fully supported*/
	case 16:	/* 4bpp*/
	{
		extern MWPALENTRY	mwstdpal4[16];
		stdpal = mwstdpal4;
	}
	break;
#endif

#if !defined(NOSTDPAL8) /* don't require large stdpal8 if not needed */
	case 256:	/* 8bpp*/
	{
		extern MWPALENTRY	mwstdpal8[256];
#if xxxALPHABLEND
		/* don't change uniform palette if alpha blending*/
		gr_firstuserpalentry = 256;
#else
		/* start after last system-reserved color*/
		gr_firstuserpalentry = FIRSTUSERPALENTRY;
#endif
		stdpal = mwstdpal8;
	} 
	break;
#endif	/* !defined(NOSTDPAL8)*/

	default:	/* truecolor*/
		/* no palette*/
		gr_firstuserpalentry = 0;
		stdpal = NULL;
	}

	/* reset next user palette entry, write hardware palette*/
	GdResetPalette();
	GdSetPalette(psd, 0, (int)psd->ncolors, stdpal);
#if xxxALPHABLEND
	/* one-time create alpha lookup table for 8bpp systems (takes ~1 sec)*/
	if(psd->ncolors == 256)
		init_alpha_lookup();
#endif

#if !NOFONTSORCLIPPING
	/* init local vars*/
	GdSetMode(MWMODE_SET);
	GdSetForeground(GdFindColor(MWRGB(255, 255, 255)));	/* WHITE*/
	GdSetBackground(GdFindColor(MWRGB(0, 0, 0)));		/* BLACK*/
	GdSetUseBackground(TRUE);
	GdSetFont(GdCreateFont(psd, MWFONT_SYSTEM_VAR, 0, NULL));
#if DYNAMICREGIONS
	GdSetClipRegion(psd, 
		GdAllocRectRegion(0, 0, psd->xvirtres, psd->yvirtres));
#else
	GdSetClipRects(psd, 0, NULL);
#endif /* DYNAMICREGIONS*/
#endif /* NOFONTSORCLIPPING*/

	/* fill black (actually fill to first palette entry or truecolor 0*/
	psd->FillRect(psd, 0, 0, psd->xvirtres-1, psd->yvirtres-1, 0);
	return psd;
}

/*
 * Close low level graphics driver
 */
void 
GdCloseScreen(PSD psd)
{
	psd->Close(psd);
}

/*
 * Return about the screen.
 */
void
GdGetScreenInfo(PSD psd, PMWSCREENINFO psi)
{
	psd->GetScreenInfo(psd, psi);
	GdGetButtonInfo(&psi->buttons);
	GdGetModifierInfo(&psi->modifiers, NULL);
	GdGetCursorPos(&psi->xpos, &psi->ypos);
}

/* reset palette to empty except for system colors*/
void
GdResetPalette(void)
{
	/* note: when palette entries are changed, all 
	 * windows may need to be redrawn
	 */
	gr_nextpalentry = gr_firstuserpalentry;
}

/* set the system palette section to the passed palette entries*/
void
GdSetPalette(PSD psd, int first, int count, MWPALENTRY *palette)
{
	int	i;

	/* no palette management needed if running truecolor*/
	if(psd->pixtype != MWPF_PALETTE)
		return;

	/* bounds check against # of device color entries*/
	if(first + count > (int)psd->ncolors)
		count = (int)psd->ncolors - first;
	if(count >= 0 && first < (int)psd->ncolors) {
		psd->SetPalette(psd, first, count, palette);

		/* copy palette for GdFind*Color*/
		for(i=0; i<count; ++i)
			gr_palette[i+first] = palette[i];
	}
}

/* get system palette entries, return count*/
int
GdGetPalette(PSD psd, int first, int count, MWPALENTRY *palette)
{
	int	i;

	/* no palette if running truecolor*/
	if(psd->pixtype != MWPF_PALETTE)
		return 0;

	/* bounds check against # of device color entries*/
	if(first + count > (int)psd->ncolors)
		if( (count = (int)psd->ncolors - first) <= 0)
			return 0;

	for(i=0; i<count; ++i)
		*palette++ = gr_palette[i+first];

	return count;
}

/*
 * Convert a palette-independent value to a hardware color
 */
MWPIXELVAL
GdFindColor(MWCOLORVAL c)
{
	/*
	 * Handle truecolor displays.  Note that the MWF_PALINDEX
	 * bit is ignored when running truecolor drivers.
	 */
	switch(gr_sinfo.pixtype) {
	case MWPF_TRUECOLOR0888:
	case MWPF_TRUECOLOR888:
		/* create 24 bit 8/8/8 pixel (0x00RRGGBB) from RGB colorval*/
		/*RGB2PIXEL888(REDVALUE(c), GREENVALUE(c), BLUEVALUE(c))*/
		return COLOR2PIXEL888(c);

	case MWPF_TRUECOLOR565:
		/* create 16 bit 5/6/5 format pixel from RGB colorval*/
		/*RGB2PIXEL565(REDVALUE(c), GREENVALUE(c), BLUEVALUE(c))*/
		return COLOR2PIXEL565(c);

	case MWPF_TRUECOLOR555:
		/* create 16 bit 5/5/5 format pixel from RGB colorval*/
		/*RGB2PIXEL555(REDVALUE(c), GREENVALUE(c), BLUEVALUE(c))*/
		return COLOR2PIXEL555(c);

	case MWPF_TRUECOLOR332:
		/* create 8 bit 3/3/2 format pixel from RGB colorval*/
		/*RGB2PIXEL332(REDVALUE(c), GREENVALUE(c), BLUEVALUE(c))*/
		return COLOR2PIXEL332(c);
	}

	/* case MWPF_PALETTE: must be running 1, 2, 4 or 8 bit palette*/

	/*
	 * Check if color is a palette index.  Note that the index
	 * isn't error checked against the system palette, for speed.
	 */
	if(c & MWF_PALINDEX)
		return (c & 0xff);

	/* search palette for closest match*/
	return GdFindNearestColor(gr_palette, (int)gr_sinfo.ncolors, c);
}

/*
 * Search a palette to find the nearest color requested.
 * Uses a weighted squares comparison.
 */
MWPIXELVAL
GdFindNearestColor(MWPALENTRY *pal, int size, MWCOLORVAL cr)
{
	MWPALENTRY *	rgb;
	int		r, g, b;
	int		R, G, B;
	long		diff = 0x7fffffffL;
	long		sq;
	int		best = 0;

	r = REDVALUE(cr);
	g = GREENVALUE(cr);
	b = BLUEVALUE(cr);
	for(rgb=pal; diff && rgb < &pal[size]; ++rgb) {
		R = rgb->r - r;
		G = rgb->g - g;
		B = rgb->b - b;
#if 1
		/* speedy linear distance method*/
		sq = abs(R) + abs(G) + abs(B);
#else
		/* slower distance-cubed with luminance adjustment*/
		/* gray is .30R + .59G + .11B*/
		/* = (R*77 + G*151 + B*28)/256*/
		sq = (long)R*R*30*30 + (long)G*G*59*59 + (long)B*B*11*11;
#endif

		if(sq < diff) {
			best = rgb - pal;
			if((diff = sq) == 0)
				return best;
		}
	}
	return best;
}

#if !VXWORKS
#include <unistd.h>
#include <fcntl.h>
/* capture the screen contents to a file for later makebmp processing*/
int
GdCaptureScreen(char *path)
{
	int n, ifd, ofd;
	long i;
	char buf[256];

	ifd = open("/dev/fb0", 0);
	ofd = creat(path, 0666);
	for(n=0; n<256; ++n)
		write(ofd, &gr_palette[n], 3);
	for(i=scrdev.xvirtres*scrdev.yvirtres; i > 0; ) {
		if((n = read(ifd, buf, 256)) > 0) {
			write(ofd, buf, n);
			i -= n;
		}
	}
	close(ifd);
	close(ofd);
	return (ifd == -1 || ofd == -1);
}
#endif /* !VXWORKS*/
