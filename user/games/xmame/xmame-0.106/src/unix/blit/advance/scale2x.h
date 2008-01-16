/* scale2x algorithm (Andrea Mazzoleni, http://advancemame.sourceforge.net):
 *
 * A 9-pixel rectangle is taken from the source bitmap:
 *
 *  a b c
 *  d e f
 *  g h i
 *
 * The central pixel e is expanded into four new pixels,
 *
 *  e0 e1
 *  e2 e3
 *
 * where
 *
 *  e0 = (d == b && b != f && d != h) ? d : e;
 *  e1 = (b == f && b != d && f != h) ? f : e;
 *  e2 = (d == h && d != b && h != f) ? d : e;
 *  e3 = (h == f && d != h && b != f) ? f : e;
 *
 * Copyright stuff:
 * 
 * 1st According to the copyright header in the original C file this code is
 * DUAL licensed under:
 * A) GPL (with an extra clause)(see file COPYING)
 * B) you are allowed to use this code in your program with these conditions:
 *    - the program is not used in commercial activities.
 *    - the whole source code of the program is released with the binary.
 *    - derivative works of the program are allowed.
 * IANAL but IMHO xmame matches the demands for B.
 *
 * 2nd the version of the GPL used contains this extra clause:
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
 * 3th The person who originaly incorperated this effect into
 * xmame, got explicited permission, see permession.txt.
 *
 * J.W.R. de Goede, Rotterdam the Netherlands, 17 december 2004.
 */

INLINE void FUNC_NAME(blit_scale2x_border) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, unsigned int *lookup)
{
  while (src1 < end1) {
    if (src1[-1] == src0[0] && src2[0] != src0[0] && src1[ 1] != src0[0])
      *dst++ = GETPIXEL(src0[0]);
    else *dst++ = GETPIXEL(src1[0]);

    if (src1[ 1] == src0[0] && src2[0] != src0[0] && src1[-1] != src0[0])
      *dst++ = GETPIXEL(src0[0]);
    else *dst++ = GETPIXEL(src1[0]);

    src0++;
    src1++;
    src2++;
  }
}

INLINE void FUNC_NAME(blit_scale2x_center) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, unsigned int *lookup)
{
  while (src1 < end1) {
    if (src0[0] != src2[0] && src1[-1] != src1[1]) {
            *dst++ = GETPIXEL((src1[-1] == src0[0] && src1[0] != src2[-1]) || (src1[-1] == src2[0] && src1[0] != src0[-1]) ? src1[-1] : src1[0]);
            *dst++ = GETPIXEL((src1[1] == src0[0] && src1[0] != src2[1]) || (src1[1] == src2[0] && src1[0] != src0[1]) ? src1[1] : src1[0]);
    } else {
            *dst++ = GETPIXEL(src1[0]);
            *dst++ = GETPIXEL(src1[0]);
    }
    src0++;
    src1++;
    src2++;
  }
}

INLINE void FUNC_NAME(blit_scale2x2_line) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  FUNC_NAME(blit_scale2x_border)(src0, src1, src2, end1, dst, lookup);
  FUNC_NAME(blit_scale2x_border)(src2, src1, src0, end1, dst + dest_width,
    lookup);
}

INLINE void FUNC_NAME(blit_scale2x3_line) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  FUNC_NAME(blit_scale2x_border)(src0, src1, src2, end1, dst, lookup);
  FUNC_NAME(blit_scale2x_center)(src0, src1, src2, end1, dst + dest_width,
    lookup);
  FUNC_NAME(blit_scale2x_border)(src2, src1, src0, end1, dst + 2*dest_width,
    lookup);
}

INLINE void FUNC_NAME(blit_scale2x4_line) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  FUNC_NAME(blit_scale2x_border)(src0, src1, src2, end1, dst, lookup);
  FUNC_NAME(blit_scale2x_center)(src0, src1, src2, end1, dst + dest_width,
    lookup);
  memcpy(dst + 2*dest_width, dst + dest_width,
    (end1-src1)*sizeof(RENDER_PIXEL)*2);
  FUNC_NAME(blit_scale2x_border)(src2, src1, src0, end1, dst + 3*dest_width,
    lookup);
}

INLINE void FUNC_NAME(blit_scale2x4_line_dfb) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  FUNC_NAME(blit_scale2x_border)(src0, src1, src2, end1, dst, lookup);
  FUNC_NAME(blit_scale2x_center)(src0, src1, src2, end1, dst + dest_width,
    lookup);
  FUNC_NAME(blit_scale2x_center)(src0, src1, src2, end1, dst + 2*dest_width,
    lookup);
  FUNC_NAME(blit_scale2x_border)(src2, src1, src0, end1, dst + 3*dest_width,
    lookup);
}

INLINE void FUNC_NAME(blit_scale2x5_line) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  FUNC_NAME(blit_scale2x_border)(src0, src1, src2, end1, dst, lookup);
  memcpy(dst + dest_width, dst, (end1-src1)*sizeof(RENDER_PIXEL)*2);
  FUNC_NAME(blit_scale2x_center)(src0, src1, src2, end1, dst + 2*dest_width,
    lookup);
  FUNC_NAME(blit_scale2x_border)(src2, src1, src0, end1, dst + 3*dest_width,
    lookup);
  memcpy(dst + 4*dest_width, dst + 3*dest_width,
    (end1-src1)*sizeof(RENDER_PIXEL)*2);
}

INLINE void FUNC_NAME(blit_scale2x5_line_dfb) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  FUNC_NAME(blit_scale2x_border)(src0, src1, src2, end1, dst, lookup);
  FUNC_NAME(blit_scale2x_border)(src0, src1, src2, end1, dst + dest_width,
    lookup);
  FUNC_NAME(blit_scale2x_center)(src0, src1, src2, end1, dst + 2*dest_width,
    lookup);
  FUNC_NAME(blit_scale2x_border)(src2, src1, src0, end1, dst + 3*dest_width,
    lookup);
  FUNC_NAME(blit_scale2x_border)(src2, src1, src0, end1, dst + 4*dest_width,
    lookup);
}

INLINE void FUNC_NAME(blit_scale2x6_line) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  FUNC_NAME(blit_scale2x_border)(src0, src1, src2, end1, dst, lookup);
  memcpy(dst + dest_width, dst,
    (end1-src1)*sizeof(RENDER_PIXEL)*2);
  FUNC_NAME(blit_scale2x_center)(src0, src1, src2, end1, dst + 2*dest_width,
    lookup);
  memcpy(dst + 3*dest_width, dst + 2*dest_width,
    (end1-src1)*sizeof(RENDER_PIXEL)*2);
  FUNC_NAME(blit_scale2x_center)(src0, src1, src2, end1, dst + 4*dest_width,
    lookup);
  memcpy(dst + 5*dest_width, dst + 4*dest_width,
    (end1-src1)*sizeof(RENDER_PIXEL)*2);
}

INLINE void FUNC_NAME(blit_scale2x6_line_dfb) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  FUNC_NAME(blit_scale2x_border)(src0, src1, src2, end1, dst, lookup);
  FUNC_NAME(blit_scale2x_border)(src0, src1, src2, end1, dst + dest_width,
    lookup);
  FUNC_NAME(blit_scale2x_center)(src0, src1, src2, end1, dst + 2*dest_width,
    lookup);
  FUNC_NAME(blit_scale2x_center)(src0, src1, src2, end1, dst + 3*dest_width,
    lookup);
  FUNC_NAME(blit_scale2x_border)(src2, src1, src0, end1, dst + 4*dest_width,
    lookup);
  FUNC_NAME(blit_scale2x_border)(src2, src1, src0, end1, dst + 5*dest_width,
    lookup);
}

INLINE void FUNC_NAME(blit_scale3x_border) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, unsigned int *lookup)
{
  while (src1 < end1) {
    if (src0[0] != src2[0] && src1[-1] != src1[1]) {
    	*dst++ = GETPIXEL(src1[-1] == src0[0] ? src1[-1] : src1[0]);
    	*dst++ = GETPIXEL((src1[-1] == src0[0] && src1[0] != src0[1]) || (src1[1] == src0[0] && src1[0] != src0[-1]) ? src0[0] : src1[0]);
    	*dst++ = GETPIXEL(src1[1] == src0[0] ? src1[1] : src1[0]);
    } else {
    	*dst++ = GETPIXEL(src1[0]);
    	*dst++ = GETPIXEL(src1[0]);
    	*dst++ = GETPIXEL(src1[0]);
    }
    src0++;
    src1++;
    src2++;
  }
}

INLINE void FUNC_NAME(blit_scale3x_center) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, unsigned int *lookup)
{
  while (src1 < end1) {
    if (src0[0] != src2[0] && src1[-1] != src1[1]) {
    	*dst++ = GETPIXEL((src1[-1] == src0[0] && src1[0] != src2[-1]) || (src1[-1] == src2[0] && src1[0] != src0[-1]) ? src1[-1] : src1[0]);
    	*dst++ = GETPIXEL(src1[0]);
    	*dst++ = GETPIXEL((src1[1] == src0[0] && src1[0] != src2[1]) || (src1[1] == src2[0] && src1[0] != src0[1]) ? src1[1] : src1[0]);
    } else {
    	*dst++ = GETPIXEL(src1[0]);
    	*dst++ = GETPIXEL(src1[0]);
    	*dst++ = GETPIXEL(src1[0]);
    }
    src0++;
    src1++;
    src2++;
  }
}

INLINE void FUNC_NAME(blit_scale3x2_line) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  FUNC_NAME(blit_scale3x_border)(src0, src1, src2, end1, dst, lookup);
  FUNC_NAME(blit_scale3x_border)(src2, src1, src0, end1, dst + dest_width,
    lookup);
}

INLINE void FUNC_NAME(blit_scale3x3_line) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  FUNC_NAME(blit_scale3x_border)(src0, src1, src2, end1, dst, lookup);
  FUNC_NAME(blit_scale3x_center)(src0, src1, src2, end1, dst + dest_width,
    lookup);
  FUNC_NAME(blit_scale3x_border)(src2, src1, src0, end1, dst + 2*dest_width,
    lookup);
}

INLINE void FUNC_NAME(blit_scale3x4_line) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  FUNC_NAME(blit_scale3x_border)(src0, src1, src2, end1, dst, lookup);
  FUNC_NAME(blit_scale3x_center)(src0, src1, src2, end1, dst + dest_width,
    lookup);
  memcpy(dst + 2*dest_width, dst + dest_width,
    (end1-src1)*sizeof(RENDER_PIXEL)*3);
  FUNC_NAME(blit_scale3x_border)(src2, src1, src0, end1, dst + 3*dest_width,
    lookup);
}

INLINE void FUNC_NAME(blit_scale3x4_line_dfb) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  FUNC_NAME(blit_scale3x_border)(src0, src1, src2, end1, dst, lookup);
  FUNC_NAME(blit_scale3x_center)(src0, src1, src2, end1, dst + dest_width,
    lookup);
  FUNC_NAME(blit_scale3x_center)(src0, src1, src2, end1, dst + 2*dest_width,
    lookup);
  FUNC_NAME(blit_scale3x_border)(src2, src1, src0, end1, dst + 3*dest_width,
    lookup);
}

INLINE void FUNC_NAME(blit_scale3x5_line) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  FUNC_NAME(blit_scale3x_border)(src0, src1, src2, end1, dst, lookup);
  memcpy(dst + dest_width, dst,
    (end1-src1)*sizeof(RENDER_PIXEL)*3);
  FUNC_NAME(blit_scale3x_center)(src0, src1, src2, end1, dst + 2*dest_width,
    lookup);
  FUNC_NAME(blit_scale3x_border)(src2, src1, src0, end1, dst + 3*dest_width,
    lookup);
  memcpy(dst + 4*dest_width, dst + 3*dest_width,
    (end1-src1)*sizeof(RENDER_PIXEL)*3);
}

INLINE void FUNC_NAME(blit_scale3x5_line_dfb) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  FUNC_NAME(blit_scale3x_border)(src0, src1, src2, end1, dst, lookup);
  FUNC_NAME(blit_scale3x_border)(src0, src1, src2, end1, dst + dest_width,
    lookup);
  FUNC_NAME(blit_scale3x_center)(src0, src1, src2, end1, dst + 2*dest_width,
    lookup);
  FUNC_NAME(blit_scale3x_border)(src2, src1, src0, end1, dst + 3*dest_width,
    lookup);
  FUNC_NAME(blit_scale3x_border)(src2, src1, src0, end1, dst + 4*dest_width,
    lookup);
}

INLINE void FUNC_NAME(blit_scale3x6_line) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  FUNC_NAME(blit_scale3x_border)(src0, src1, src2, end1, dst, lookup);
  memcpy(dst + dest_width, dst,
    (end1-src1)*sizeof(RENDER_PIXEL)*3);
  FUNC_NAME(blit_scale3x_center)(src0, src1, src2, end1, dst + 2*dest_width,
    lookup);
  memcpy(dst + 3*dest_width, dst + 2*dest_width,
    (end1-src1)*sizeof(RENDER_PIXEL)*3);
  FUNC_NAME(blit_scale3x_border)(src2, src1, src0, end1, dst + 4*dest_width,
    lookup);
  memcpy(dst + 5*dest_width, dst + 4*dest_width,
    (end1-src1)*sizeof(RENDER_PIXEL)*3);
}

INLINE void FUNC_NAME(blit_scale3x6_line_dfb) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  RENDER_PIXEL *dst, int dest_width, unsigned int *lookup)
{
  FUNC_NAME(blit_scale3x_border)(src0, src1, src2, end1, dst, lookup);
  FUNC_NAME(blit_scale3x_border)(src0, src1, src2, end1, dst + dest_width,
    lookup);
  FUNC_NAME(blit_scale3x_center)(src0, src1, src2, end1, dst + 2*dest_width,
    lookup);
  FUNC_NAME(blit_scale3x_center)(src0, src1, src2, end1, dst + 3*dest_width,
    lookup);
  FUNC_NAME(blit_scale3x_border)(src2, src1, src0, end1, dst + 4*dest_width,
    lookup);
  FUNC_NAME(blit_scale3x_border)(src2, src1, src0, end1, dst + 5*dest_width,
    lookup);
}

BLIT_BEGIN(blit_scale2x)
  switch(sysdep_display_params.widthscale)
  {
    case 2:
      switch(sysdep_display_params.heightscale)
      {
        case 2:
          BLIT_LOOP2X(blit_scale2x2_line, 2);
          break;
        case 3:
          BLIT_LOOP2X(blit_scale2x3_line, 3);
          break;
        case 4:
          if (sysdep_display_properties.mode_info[
              sysdep_display_params.video_mode] & SYSDEP_DISPLAY_DIRECT_FB)
          {
            BLIT_LOOP2X(blit_scale2x4_line_dfb, 4);
          }
          else
          {
            BLIT_LOOP2X(blit_scale2x4_line, 4);
          }
          break;
        case 5:
          if (sysdep_display_properties.mode_info[
              sysdep_display_params.video_mode] & SYSDEP_DISPLAY_DIRECT_FB)
          {
            BLIT_LOOP2X(blit_scale2x5_line_dfb, 5);
          }
          else
          {
            BLIT_LOOP2X(blit_scale2x5_line, 5);
          }
          break;
        case 6:
          if (sysdep_display_properties.mode_info[
              sysdep_display_params.video_mode] & SYSDEP_DISPLAY_DIRECT_FB)
          {
            BLIT_LOOP2X(blit_scale2x6_line_dfb, 6);
          }
          else
          {
            BLIT_LOOP2X(blit_scale2x6_line, 6);
          }
          break;
      }
      break;
    case 3:
      switch(sysdep_display_params.heightscale)
      {
        case 2:
          BLIT_LOOP2X(blit_scale3x2_line, 2);
          break;
        case 3:
          BLIT_LOOP2X(blit_scale3x3_line, 3);
          break;
        case 4:
          if (sysdep_display_properties.mode_info[
              sysdep_display_params.video_mode] & SYSDEP_DISPLAY_DIRECT_FB)
          {
            BLIT_LOOP2X(blit_scale3x4_line_dfb, 4);
          }
          else
          {
            BLIT_LOOP2X(blit_scale3x4_line, 4);
          }
          break;
        case 5:
          if (sysdep_display_properties.mode_info[
              sysdep_display_params.video_mode] & SYSDEP_DISPLAY_DIRECT_FB)
          {
            BLIT_LOOP2X(blit_scale3x5_line_dfb, 5);
          }
          else
          {
            BLIT_LOOP2X(blit_scale3x5_line, 5);
          }
          break;
        case 6:
          if (sysdep_display_properties.mode_info[
              sysdep_display_params.video_mode] & SYSDEP_DISPLAY_DIRECT_FB)
          {
            BLIT_LOOP2X(blit_scale3x6_line_dfb, 6);
          }
          else
          {
            BLIT_LOOP2X(blit_scale3x6_line, 6);
          }
          break;
      }
      break;
  }
BLIT_END
