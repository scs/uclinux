/*
 * hq2x algorithm (C) 2003 by Maxim Stepin (www.hiend3d.com/hq2x.html)
 * lq2x algorithm (C) 2003 by Andrea Mazzoleni
 * (http://advancemame.sourceforge.net)
 * Initial xmame implementations by Pieter Hulshoff.
 * The current implementions are a mix between Pieter Hulshoff's
 * implementation, and the one from advancemame (Hans de Goede).
 *
 * hq2x is a fast, high-quality 2x magnification filter.
 * lq2x is a fast, low-quality 2x magnification filter.
 *
 * The first step is an analysis of the 3x3 area of the source pixel. The
 * central pixel gets compared with its 8 nearest neighbors. For lq2x
 * the pixels are sorted into the categories: "equal" and "unequel".
 * For hq2x we calculate the color difference and compare this to a predefined
 * threshold, resulting in the categories: "close" and "distant" colored.
 * There are 8 neighbors, so we are getting 256 possible combinations.
 * 
 * For the next step, which is filtering, a lookup table with 256 entries is
 * used, one entry per each combination of close/distant colored neighbors.
 * Each entry describes how to mix the colors of the source pixels from 3x3
 * area to get interpolated pixels of the filtered image.
 *
 * The present hq2x implementation is using YUV color space to calculate color
 * differences, with more tolerance on Y (brightness) component, then on
 * color components U and V.
 *
 * Creating a lookup table was the most difficult part - for each
 * combination the most probable vector representation of the area has to be
 * determined, with the idea of edges between the different colored areas of
 * the image to be preserved, with the edge direction to be as close to a
 * correct one as possible. That vector representation is then rasterised
 * with higher (2x) resolution using anti-aliasing, and the result is stored
 * in the lookup table.
 * The filter was not designed for photographs, but for images with clear
 * sharp edges, like line graphics or cartoon sprites. It was also designed
 * to be fast enough to process 256x256 images in real-time.
 *
 * Copyright stuff:
 * 
 * 1st According to the copyright headers in advancemame the advancemame code
 * is licensed under the GPL with this extra clause (see file COPYING):
 *
 ****************************************************************************
 * 
 * The AdvanceMAME/MESS sources are released under the
 * GNU General Public License (GPL) with this special exception
 * added to every source file :
 * 
 *     "In addition, as a special exception, Andrea Mazzoleni
 *     gives permission to link the code of this program with
 *     the MAME library (or with modified versions of MAME that use the
 *     same license as MAME), and distribute linked combinations including
 *     the two.  You must obey the GNU General Public License in all
 *     respects for all of the code used other than MAME.  If you modify
 *     this file, you may extend this exception to your version of the
 *     file, but you are not obligated to do so.  If you do not wish to
 *     do so, delete this exception statement from your version."
 * 
 * This imply that if you distribute a binary version of AdvanceMAME/MESS
 * linked with the MAME and MESS sources you must also follow the MAME
 * License.
 *
 ****************************************************************************
 *
 * So basicly this code may be distributed under the MAME license, as is
 * xmame
 *
 * 2nd The person who originaly incorperated this effect into
 * xmame, got explicited permission, see permession.txt.
 *
 * J.W.R. de Goede, Rotterdam the Netherlands, 17 december 2004.
 */

/* Configuration defines and includes */
#define XQ2X_GETPIXEL(p) GETPIXEL(p)
#define HQ2X_YUVLOOKUP(p) effect_rgb2yuv[p]
#include "xq2x_defs.h"

/* Pixel glue define, so that we can use the advancemame lookup
   tables unmodified. */
#define P(a, b) dst##b[a]

INLINE void XQ2X_FUNC_NAME(blit_xq2x_line_2x2) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  RENDER_PIXEL *dst0 = dst;
  RENDER_PIXEL *dst1 = dst + dest_width;

  XQ2X_LINE_LOOP_BEGIN
    switch (XQ2X_FUNC_NAME(xq2x_make_mask)(c)) {
      #ifdef HQ2X
      #  include "hq2x.dat"
      #else
      #  include "lq2x.dat"
      #endif
    }
    dst0 += 2;
    dst1 += 2;
  XQ2X_LINE_LOOP_END
}

INLINE void XQ2X_FUNC_NAME(blit_xq2x_line_2x3) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  RENDER_PIXEL *dst0 = dst;
  RENDER_PIXEL *dst1 = dst + dest_width;
  RENDER_PIXEL *dst2 = dst + 2*dest_width;
  
  XQ2X_LINE_LOOP_BEGIN
    switch (XQ2X_FUNC_NAME(xq2x_make_mask)(c)) {
      #ifdef HQ2X
      #  include "hq2x3.dat"
      #else
      #  include "lq2x3.dat"
      #endif
    }
    dst0 += 2;
    dst1 += 2;
    dst2 += 2;
  XQ2X_LINE_LOOP_END
}

#undef P
#define P(a, b) dst##a[b]

INLINE void XQ2X_FUNC_NAME(blit_xq2x_line_3x2) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  RENDER_PIXEL *dst0 = dst;
  RENDER_PIXEL *dst1 = dst + dest_width;

  XQ2X_LINE_LOOP_BEGIN_SWAP_XY
    switch (XQ2X_FUNC_NAME(xq2x_make_mask)(c)) {
      #ifdef HQ2X
      #  include "hq2x3.dat"
      #else
      #  include "lq2x3.dat"
      #endif
    }
    dst0 += 3;
    dst1 += 3;
  XQ2X_LINE_LOOP_END
}

#undef P
#define P(a, b) dst##b[a]

INLINE void XQ2X_FUNC_NAME(blit_xq2x_line_3x3) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  RENDER_PIXEL *dst0 = dst;
  RENDER_PIXEL *dst1 = dst + dest_width;
  RENDER_PIXEL *dst2 = dst + 2*dest_width;

  XQ2X_LINE_LOOP_BEGIN
    switch (XQ2X_FUNC_NAME(xq2x_make_mask)(c)) {
      #ifdef HQ2X
      #  include "hq3x.dat"
      #else
      #  include "lq3x.dat"
      #endif
    }
    dst0 += 3;
    dst1 += 3;
    dst2 += 3;
  XQ2X_LINE_LOOP_END
}

#undef P

BLIT_BEGIN(XQ2X_NAME(blit))
  switch(sysdep_display_params.widthscale)
  {
    case 2:
      switch(sysdep_display_params.heightscale)
      {
        case 2:
          if (sysdep_display_properties.mode_info[
              sysdep_display_params.video_mode] & SYSDEP_DISPLAY_DIRECT_FB) {
            BLIT_LOOP2X_DFB(XQ2X_NAME(blit_xq2x_line_2x2), 2)
          } else {
            BLIT_LOOP2X(XQ2X_NAME(blit_xq2x_line_2x2), 2)
          }
          break;
        case 3:
          if (sysdep_display_properties.mode_info[
              sysdep_display_params.video_mode] & SYSDEP_DISPLAY_DIRECT_FB) {
            BLIT_LOOP2X_DFB(XQ2X_NAME(blit_xq2x_line_2x3), 3)
          } else {
            BLIT_LOOP2X(XQ2X_NAME(blit_xq2x_line_2x3), 3)
          }
          break;
      }
      break;
    case 3:
      switch(sysdep_display_params.heightscale)
      {
        case 2:
          if (sysdep_display_properties.mode_info[
              sysdep_display_params.video_mode] & SYSDEP_DISPLAY_DIRECT_FB) {
            BLIT_LOOP2X_DFB(XQ2X_NAME(blit_xq2x_line_3x2), 2)
          } else {
            BLIT_LOOP2X(XQ2X_NAME(blit_xq2x_line_3x2), 2)
          }
          break;
        case 3:
          if (sysdep_display_properties.mode_info[
              sysdep_display_params.video_mode] & SYSDEP_DISPLAY_DIRECT_FB) {
            BLIT_LOOP2X_DFB(XQ2X_NAME(blit_xq2x_line_3x3), 3)
          } else {
            BLIT_LOOP2X(XQ2X_NAME(blit_xq2x_line_3x3), 3)
          }
          break;
      }
      break;
  }
BLIT_END

#include "xq2x_undefs.h"
