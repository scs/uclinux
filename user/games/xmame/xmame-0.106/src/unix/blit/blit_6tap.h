#define _6TAP_CLIP(a) (((a) < 0) ? 0 : (((a) > 0xff) ? 0xff : (a)))

#if SRC_DEPTH == 15
#  define _6TAP_GETPIXEL(p) lookup[p]
#  define _6TAP_ADDLINE(NAME) NAME##_addline_15
#elif SRC_DEPTH == 16
#  define _6TAP_GETPIXEL(p) lookup[p]
#  define _6TAP_ADDLINE(NAME) NAME##_addline_16
#else
#  define _6TAP_GETPIXEL(p) (p)
#  define _6TAP_ADDLINE(NAME) NAME##_addline_32
#endif

#ifdef RENDER_YUY2
#  define _6TAP_RENDER_LINE(NAME) NAME##_render_line_yuy2
#elif RENDER_DEPTH == 15
#  define _6TAP_RENDER_LINE(NAME) NAME##_render_line_15
#elif RENDER_DEPTH == 16
#  define _6TAP_RENDER_LINE(NAME) NAME##_render_line_16
#else
#  define _6TAP_RENDER_LINE(NAME) NAME##_render_line_32
#endif


/* only 3 versions of addline and render_line: 15, 16 and 32 */
#if SRC_DEPTH==DEST_DEPTH && !defined RENDER_YUY2
void _6TAP_ADDLINE(blit_6tap)(SRC_PIXEL *src, unsigned int count,
  unsigned int *lookup)
{
  unsigned int *u32dest;
  unsigned char *u8dest;
  int pixel;
  unsigned int i;
  char *tmp;

  /* first, move the existing lines up by one */
  tmp = _6tap2x_buf0;
  _6tap2x_buf0 = _6tap2x_buf1;
  _6tap2x_buf1 = _6tap2x_buf2;
  _6tap2x_buf2 = _6tap2x_buf3;
  _6tap2x_buf3 = _6tap2x_buf4;
  _6tap2x_buf4 = _6tap2x_buf5;
  _6tap2x_buf5 = tmp;

  /* if there's no new line, clear the last one and return */
  if (!src)
  {
    memset(_6tap2x_buf5, 0, count << 3);
    return;
  }

  /* we have a new line, so first do the palette lookup and zoom by 2 */
  u32dest = (unsigned int *) _6tap2x_buf5;
  for (i = 0; i < count; i++)
  {
    *u32dest++ = _6TAP_GETPIXEL(*src);
    src++;
    u32dest++;
  }

  /* just replicate the first 2 and last 3 pixels */
  u32dest[-1] = u32dest[-2];
  u32dest[-3] = u32dest[-4];
  u32dest[-5] = u32dest[-6];
  u32dest = (unsigned int *) _6tap2x_buf5;
  u32dest[1] = u32dest[0];
  u32dest[3] = u32dest[2];

  /* finally, do the horizontal 6-tap filter for the remaining half-pixels */
  u8dest = ((unsigned char *) _6tap2x_buf5) + 20;
  for (i = 2; i < count - 3; i++)
    {
#ifndef LSB_FIRST
	/* clear the first byte */
	*u8dest++ = 0;
#endif
	/* first, do the blue part (on LSB_FIRST, on MSB_FIRST the red) */
	pixel = (((int)  u8dest[-4] + (int) u8dest[4]) << 2) -
	         ((int) u8dest[-12] + (int) u8dest[12]);
	pixel += pixel << 2;
	pixel += ((int) u8dest[-20] + (int) u8dest[20]);
	pixel = (pixel + 0x10) >> 5;
	*u8dest++ = _6TAP_CLIP(pixel);
	/* next, do the green part */
	pixel = (((int)  u8dest[-4] + (int) u8dest[4]) << 2) -
	         ((int) u8dest[-12] + (int) u8dest[12]);
	pixel += pixel << 2;
	pixel += ((int) u8dest[-20] + (int) u8dest[20]);
	pixel = (pixel + 0x10) >> 5;
	*u8dest++ = _6TAP_CLIP(pixel);
	/* last, do the red part (on LSB_FIRST, on MSB_FIRST the blue) */
	pixel = (((int)  u8dest[-4] + (int) u8dest[4]) << 2) -
	         ((int) u8dest[-12] + (int) u8dest[12]);
	pixel += pixel << 2;
	pixel += ((int) u8dest[-20] + (int) u8dest[20]);
	pixel = (pixel + 0x10) >> 5;
	*u8dest++ = _6TAP_CLIP(pixel);
#ifdef LSB_FIRST
	/* clear the last byte */
	*u8dest++ = 0;
#endif
	u8dest += 4;
    }
}

void _6TAP_RENDER_LINE(blit_6tap)(RENDER_PIXEL *dst0, RENDER_PIXEL *dst1,
  unsigned int count)
{
  unsigned char *src0 = (unsigned char *) _6tap2x_buf0;
  unsigned char *src1 = (unsigned char *) _6tap2x_buf1;
  unsigned char *src2 = (unsigned char *) _6tap2x_buf2;
  unsigned char *src3 = (unsigned char *) _6tap2x_buf3;
  unsigned char *src4 = (unsigned char *) _6tap2x_buf4;
  unsigned char *src5 = (unsigned char *) _6tap2x_buf5;
  unsigned int *src32 = (unsigned int *) _6tap2x_buf2;
  unsigned int i;
  int p1, p2, p3;

  /* first we need to just copy the 3rd line into the first destination line */
  for (i = 0; i < (count << 1); i++)
    {
	*dst0++ = RGB32_TO_RENDER_PIXEL(*src32);
	src32++;
    }

  /* then we need to vertically filter for the second line */
  for (i = 0; i < (count << 1); i++)
    {
#ifndef LSB_FIRST
	src0++; src1++; src2++; src3++; src4++; src5++;
#endif
	/* first, do p1 */
	p1 = (((int) *src2++ + (int) *src3++) << 2) -
	        ((int) *src1++ + (int) *src4++);
	p1 += p1 << 2;
	p1 += ((int) *src0++ + (int) *src5++);
	p1 = (p1 + 0x10) >> 5;
	p1 = _6TAP_CLIP(p1);
	p1 = p1 - (p1 >> 2);
	/* next, do p2 */
	p2 = (((int) *src2++ + (int) *src3++) << 2) -
	         ((int) *src1++ + (int) *src4++);
	p2 += p2 << 2;
	p2 += ((int) *src0++ + (int) *src5++);
	p2 = (p2 + 0x10) >> 5;
	p2 = _6TAP_CLIP(p2);
	p2 = p2 - (p2 >> 2);
	/* last, do p3 */
	p3 = (((int) *src2++ + (int) *src3++) << 2) -
	       ((int) *src1++ + (int) *src4++);
	p3 += p3 << 2;
	p3 += ((int) *src0++ + (int) *src5++);
	p3 = (p3 + 0x10) >> 5;
	p3 = _6TAP_CLIP(p3);
	p3 = p3 - (p3 >> 2);
	/* write the pixel */
#ifndef LSB_FIRST
	*dst1++ = RGB_TO_RENDER_PIXEL(p1, p2, p3);
#else
	*dst1++ = RGB_TO_RENDER_PIXEL(p3, p2, p1);
	src0++; src1++; src2++; src3++; src4++; src5++;
#endif
    }
}
#endif

#define _6TAP(NAME) \
BLIT_BEGIN(NAME) \
  blit_6tap_clear(dirty_area->max_x - dirty_area->min_x); \
  \
  if (sysdep_display_params.orientation) { \
    rotate_func(rotate_dbbuf0, bitmap, dirty_area->min_y, dirty_area); \
    _6TAP_ADDLINE(NAME)((SRC_PIXEL *)rotate_dbbuf0, \
      dirty_area->max_x - dirty_area->min_x, palette->lookup); \
    rotate_func(rotate_dbbuf0, bitmap, dirty_area->min_y+1, dirty_area); \
    _6TAP_ADDLINE(NAME)((SRC_PIXEL *)rotate_dbbuf0, \
      dirty_area->max_x - dirty_area->min_x, palette->lookup); \
    rotate_func(rotate_dbbuf0, bitmap, dirty_area->min_y+2, dirty_area); \
    _6TAP_ADDLINE(NAME)((SRC_PIXEL *)rotate_dbbuf0, \
      dirty_area->max_x - dirty_area->min_x, palette->lookup); \
    for (y = dirty_area->min_y; y < dirty_area->max_y; y++) { \
      if (y < (dirty_area->max_y - 3)) { \
        rotate_func(rotate_dbbuf0, bitmap, y+3, dirty_area); \
        _6TAP_ADDLINE(NAME)((SRC_PIXEL *)rotate_dbbuf0, \
          dirty_area->max_x - dirty_area->min_x, palette->lookup); \
      } else { \
        _6TAP_ADDLINE(NAME)(NULL, \
          dirty_area->max_x - dirty_area->min_x, palette->lookup); \
      } \
      _6TAP_RENDER_LINE(NAME)((RENDER_PIXEL *)RENDER_DEST, \
        (RENDER_PIXEL *)RENDER_DEST + RENDER_WIDTH, \
        dirty_area->max_x - dirty_area->min_x); \
      BLIT_LINE(2) \
    } \
  } else { \
    _6TAP_ADDLINE(NAME)( \
      (SRC_PIXEL *)(bitmap->line[dirty_area->min_y]) + dirty_area->min_x, \
      dirty_area->max_x - dirty_area->min_x, palette->lookup); \
    _6TAP_ADDLINE(NAME)( \
      (SRC_PIXEL *)(bitmap->line[dirty_area->min_y+1]) + dirty_area->min_x, \
      dirty_area->max_x - dirty_area->min_x, palette->lookup); \
    _6TAP_ADDLINE(NAME)( \
      (SRC_PIXEL *)(bitmap->line[dirty_area->min_y+2]) + dirty_area->min_x, \
      dirty_area->max_x - dirty_area->min_x, palette->lookup); \
    for (y = dirty_area->min_y; y < dirty_area->max_y; y++) { \
      if (y < (dirty_area->max_y - 3)) { \
        _6TAP_ADDLINE(NAME)( \
          (SRC_PIXEL *)(bitmap->line[y+3]) + dirty_area->min_x, \
          dirty_area->max_x - dirty_area->min_x, palette->lookup); \
      } else { \
        _6TAP_ADDLINE(NAME)(NULL, \
          dirty_area->max_x - dirty_area->min_x, palette->lookup); \
      } \
      _6TAP_RENDER_LINE(NAME)((RENDER_PIXEL *)RENDER_DEST, \
        (RENDER_PIXEL *)RENDER_DEST + RENDER_WIDTH, \
        dirty_area->max_x - dirty_area->min_x); \
      BLIT_LINE(2) \
    } \
  } \
BLIT_END  

_6TAP(blit_6tap)
#ifdef EFFECT_MMX_ASM
_6TAP(blit_6tap_mmx)
#endif

#undef _6TAP_CLIP
#undef _6TAP_GETPIXEL
#undef _6TAP_ADDLINE
#undef _6TAP_RENDER_LINE
#undef _6TAP
