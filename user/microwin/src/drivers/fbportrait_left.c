/*
 * Copyright (c) 2000 Greg Haerr <greg@censoft.com>
 *
 * Portrait mode subdriver for Microwindows
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "device.h"
#include "fb.h"

PSUBDRIVER _subdriver;		/* original subdriver*/

static void
fbportrait_drawpixel(PSD psd,MWCOORD x, MWCOORD y, MWPIXELVAL c)
{
	_subdriver->DrawPixel(psd, y, psd->xvirtres-x-1, c);
}

static MWPIXELVAL
fbportrait_readpixel(PSD psd,MWCOORD x, MWCOORD y)
{
	return _subdriver->ReadPixel(psd, y, psd->xvirtres-x-1);
}

static void
fbportrait_drawhorzline(PSD psd,MWCOORD x1, MWCOORD x2, MWCOORD y, MWPIXELVAL c)
{
	_subdriver->DrawVertLine(psd, y, psd->xvirtres-x2-1,
		psd->xvirtres-x1-1, c);

	/*
	 * Uncomment the following if driver doesn't support hline
	x2 = psd->xvirtres-x2-1;
	while(x2 <= (psd->xvirtres-x1-1))
		fb_drawpixel(psd, y, x2++, c);
	 */
}

static void
fbportrait_drawvertline(PSD psd,MWCOORD x, MWCOORD y1, MWCOORD y2, MWPIXELVAL c)
{
	_subdriver->DrawHorzLine(psd, y1, y2, psd->xvirtres-x-1, c);

	/*
	 * Uncomment the following if driver doesn't support vline
	while(y1 <= y2)
		fb_drawpixel(psd, y1++, psd->xvirtres-x-1, c);
	 */
}

static void
fbportrait_fillrect(PSD psd,MWCOORD x1, MWCOORD y1, MWCOORD x2, MWCOORD y2,
	MWPIXELVAL c)
{
	x2 = psd->xvirtres-x2-1;
	while(x2 <= (psd->xvirtres-x1-1))
		_subdriver->DrawHorzLine(psd, y1, y2, x2++, c);
}

static void
fbportrait_blit(PSD dstpsd,MWCOORD destx,MWCOORD desty,MWCOORD w,MWCOORD h,
	PSD srcpsd, MWCOORD srcx,MWCOORD srcy,long op)
{
	_subdriver->Blit(dstpsd, desty, dstpsd->xvirtres-destx-w, h, w,
		srcpsd, srcy, srcpsd->xvirtres-srcx-w, op);
}

SUBDRIVER fbportrait = {
	NULL,
	fbportrait_drawpixel,
	fbportrait_readpixel,
	fbportrait_drawhorzline,
	fbportrait_drawvertline,
	gen_fillrect,
	fbportrait_blit
};
