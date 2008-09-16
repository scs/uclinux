//
// "$Id: Fl_Bitmap.cxx,v 1.1.1.1 2003/08/07 21:18:39 jasonk Exp $"
//
// Bitmap drawing routines for the Fast Light Tool Kit (FLTK).
//
// Copyright 1998-1999 by Bill Spitzak and others.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Library General Public
// License as published by the Free Software Foundation; either
// version 2 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Library General Public License for more details.
//
// You should have received a copy of the GNU Library General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
// USA.
//
// Please report all bugs and problems to "fltk-bugs@easysw.com".
//

#include <FL/Fl.H>
#include <FL/x.H>
#include <FL/fl_draw.H>
#include <FL/Fl_Widget.H>
#include <FL/Fl_Menu_Item.H>
#include <FL/Fl_Bitmap.H>

void Fl_Bitmap::draw(int XP, int YP, int WP, int HP, int cx, int cy) {
  // account for current clip region (faster on Irix):
  int X,Y,W,H; fl_clip_box(XP,YP,WP,HP,X,Y,W,H);
  cx += X-XP; cy += Y-YP;
  // clip the box down to the size of image, quit if empty:
  if (cx < 0) {W += cx; X -= cx; cx = 0;}
  if ((cx+W) > w) W = w-cx;
  if (W <= 0) return;
  if (cy < 0) {H += cy; Y -= cy; cy = 0;}
  if ((cy+H) > h) H = h-cy;
  if (H <= 0) return;
#ifdef WIN32
  if (!id) {
    // we need to pad the lines out to words & swap the bits
    // in each byte.
    int w1 = (w+7)/8;
    int w2 = ((w+15)/16)*2;
    uchar* newarray = new uchar[w2*h];
    const uchar* src = array;
    uchar* dest = newarray;
    static uchar reverse[16] =	/* Bit reversal lookup table */
  		{ 0x00, 0x88, 0x44, 0xcc, 0x22, 0xaa, 0x66, 0xee,
		  0x11, 0x99, 0x55, 0xdd, 0x33, 0xbb, 0x77, 0xff };
    for (int y=0; y < h; y++) {
      for (int n = 0; n < w1; n++, src++)
	*dest++ = (reverse[*src & 0x0f] & 0xf0) |
	          (reverse[(*src >> 4) & 0x0f] & 0x0f);
      dest += w2-w1;
    }
    id = (ulong)CreateBitmap(w, h, 1, 1, newarray);
    array = newarray; // keep the pointer so I can free it later
  }
  HDC tempdc = CreateCompatibleDC(fl_gc);
  SelectObject(tempdc, (HGDIOBJ)id);
  SelectObject(fl_gc, fl_brush());
  // secret bitblt code found in old MSWindows reference manual:
  BitBlt(fl_gc, X, Y, W, H, tempdc, cx, cy, 0xE20746L);
  DeleteDC(tempdc);
#else
#if defined(NANO_X)
#if 1
  // basically as contributed by Vladimir Cotfas <unix_router@yahoo.com>
  // tweaked asthetically by SDR
  if (!id) // decode the bitmap into memory
  {
    int k = 0;
    int w1 = (w+7)/8;
    int w2 = ((w+15)/16)*2;

    uchar * new_array = new uchar [ w2 * h ];

    static uchar reverse_table [ 16 ] = // bit reversal lookup table
    {
      0x00, 0x88, 0x44, 0xCC, 0x22, 0xAA, 0x66, 0xEE,
      0x11, 0x99, 0x55, 0xDD, 0x33, 0xBB, 0x77, 0xFF
    };

    if (w < 8)
    {
      for ( int y = 0; y < h; ++y )
      {
        char p = array[y];
        new_array[k] = 0;
        new_array[k+1] =
          (reverse_table[ p    &0x0F] & 0xF0) |
          (reverse_table[(p>>4)&0x0F] & 0x0F);
        k += 2;
      }
    }
    else
    {
      uchar * dest = new_array;
      for ( int y = 0; y < h; ++y )
      {
        for ( int n = 0; n < w1; ++n, ++k )
	{
          uchar p = array[k + ((n % 2) ? -1 : 1)];
          *dest++ = 
            (reverse_table[ p    &0x0F] & 0xF0) |
	    (reverse_table[(p>>4)&0x0F] & 0x0F);
	}
        dest += w2-w1;
      }
    }
    id = (ulong)new_array;
  }
  {
    // if you don't set this the first time the bitmap is drawn in test/bitmap.cxx the background color is wrong (WHITE): all subsequent draws are correct -- why?
    GrSetGCUseBackground(fl_gc,false);
  }
  GrBitmap(fl_window,fl_gc,X,Y,W,H,(GR_BITMAP*)id);
#endif
#else
  if (!id) id = XCreateBitmapFromData(fl_display, fl_window,
				      (const char*)array, (w+7)&-8, h);
  XSetStipple(fl_display, fl_gc, id);
  int ox = X-cx; if (ox < 0) ox += w;
  int oy = Y-cy; if (oy < 0) oy += h;
  XSetTSOrigin(fl_display, fl_gc, ox, oy);
  XSetFillStyle(fl_display, fl_gc, FillStippled);
  XFillRectangle(fl_display, fl_window, fl_gc, X, Y, W, H);
  XSetFillStyle(fl_display, fl_gc, FillSolid);
#endif
#endif
}

Fl_Bitmap::~Fl_Bitmap() {
#ifdef WIN32
  if (id) {
    DeleteObject((HGDIOBJ)id);
    delete[] (uchar*)array;
  }
#else
#if defined(NANO_X)
  if (id) delete [] ((uchar*)id);
#else
  if (id) fl_delete_offscreen((Fl_Offscreen)id);
#endif
#endif
}

static void bitmap_labeltype(
    const Fl_Label* o, int x, int y, int w, int h, Fl_Align a)
{
  Fl_Bitmap* b = (Fl_Bitmap*)(o->value);
  int cx;
  if (a & FL_ALIGN_LEFT) cx = 0;
  else if (a & FL_ALIGN_RIGHT) cx = b->w-w;
  else cx = (b->w-w)/2;
  int cy;
  if (a & FL_ALIGN_TOP) cy = 0;
  else if (a & FL_ALIGN_BOTTOM) cy = b->h-h;
  else cy = (b->h-h)/2;
  fl_color((Fl_Color)o->color);
  b->draw(x,y,w,h,cx,cy);
}

static void bitmap_measure(const Fl_Label* o, int& w, int& h) {
  Fl_Bitmap* b = (Fl_Bitmap*)(o->value);
  w = b->w;
  h = b->h;
}

void Fl_Bitmap::label(Fl_Widget* o) {
  Fl::set_labeltype(_FL_BITMAP_LABEL, bitmap_labeltype, bitmap_measure);
  o->label(_FL_BITMAP_LABEL, (const char*)this);
}

void Fl_Bitmap::label(Fl_Menu_Item* o) {
  Fl::set_labeltype(_FL_BITMAP_LABEL, bitmap_labeltype, bitmap_measure);
  o->label(_FL_BITMAP_LABEL, (const char*)this);
}

//
// End of "$Id: Fl_Bitmap.cxx,v 1.1.1.1 2003/08/07 21:18:39 jasonk Exp $".
//
