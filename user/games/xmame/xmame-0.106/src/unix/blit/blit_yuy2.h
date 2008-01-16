/* yuy2 versions of the blit functions */
INLINE void FUNC_NAME(blit_normal_line_1)(SRC_PIXEL *src, SRC_PIXEL *end,
  unsigned short *dst, int dest_width, unsigned int *lookup)
{
  unsigned int p1,p2,uv;
  unsigned int *mydst = (unsigned int *)dst;
  
  while(src<end)
  {
    p1  = GET_YUV_PIXEL(*src); src++;
    p2  = GET_YUV_PIXEL(*src); src++;
    uv = (p1&UVMASK)>>1;
    uv += (p2&UVMASK)>>1;
    uv &= UVMASK;
    p1 &= Y1MASK;
    p2 &= Y2MASK;
    *mydst++ = p1|p2|uv;
  }
}

INLINE void FUNC_NAME(blit_normal_line_2)(SRC_PIXEL *src, SRC_PIXEL *end,
  unsigned short *dst, int dest_width, unsigned int *lookup)
{
  unsigned int *mydst = (unsigned int *)dst;

  while(src<end)
  {
    *mydst++ = GET_YUV_PIXEL(*src);
    src++;
  }
}

BLIT_BEGIN(blit_normal)
  switch(sysdep_display_params.widthscale)
  {
    case 1:
      BLIT_LOOP(blit_normal_line_1, 1);
      break;
    case 2:
      BLIT_LOOP(blit_normal_line_2, 1);
      break;
  }
BLIT_END

BLIT_BEGIN(blit_fakescan_h)
  switch(sysdep_display_params.widthscale)
  {
    case 1:
      BLIT_LOOP(blit_normal_line_1, 2);
      break;
    case 2:
      BLIT_LOOP(blit_normal_line_2, 2);
      break;
  }
BLIT_END

#ifndef DISABLE_EFFECTS

/* 6tap2x yuy2 render line function, we only need this once! */
#if SRC_DEPTH == 16
#define _6TAP_CLIP(a) (((a) < 0) ? 0 : (((a) > 0xff) ? 0xff : (a)))

void blit_6tap_render_line_yuy2(unsigned short *dst0, unsigned short *dst1,
  unsigned int count)
{
  unsigned char *src0 = (unsigned char *) _6tap2x_buf0;
  unsigned char *src1 = (unsigned char *) _6tap2x_buf1;
  unsigned char *src2 = (unsigned char *) _6tap2x_buf2;
  unsigned char *src3 = (unsigned char *) _6tap2x_buf3;
  unsigned char *src4 = (unsigned char *) _6tap2x_buf4;
  unsigned char *src5 = (unsigned char *) _6tap2x_buf5;
  unsigned int *src32 = (unsigned int *) _6tap2x_buf2;
  unsigned int *mydst = (unsigned int *)dst0;
  unsigned int i,y1,y2,uv;
  int p1,p2,p3;

  /* first we need to just copy the 3rd line into the first destination line */
  for (i = 0; i < count; i++)
  {
    y1 = effect_rgb2yuv[_32TO16_RGB_565(*src32)]; src32++;
    y2 = effect_rgb2yuv[_32TO16_RGB_565(*src32)]; src32++;

    uv = (y1&UVMASK)>>1;
    uv += (y2&UVMASK)>>1;
    uv &= UVMASK;
    y1 &= Y1MASK;
    y2 &= Y2MASK;
    *mydst++ = y1|y2|uv;
  }

  /* then we need to vertically filter for the second line */
  mydst = (unsigned int *)dst1;
  for (i = 0; i < count; i++)
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
    /* get the yuv value */
#ifndef LSB_FIRST
    y1 = effect_rgb2yuv[((p1&0xF8)<<8)|((p2&0xFC)<<3)|((p3&0xF8)>>3)];
#else
    y1 = effect_rgb2yuv[((p3&0xF8)<<8)|((p2&0xFC)<<3)|((p1&0xF8)>>3)];
    src0++; src1++; src2++; src3++; src4++; src5++;
#endif

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
    /* get the yuv value */
#ifndef LSB_FIRST
    y2 = effect_rgb2yuv[((p1&0xF8)<<8)|((p2&0xFC)<<3)|((p3&0xF8)>>3)];
#else
    y2 = effect_rgb2yuv[((p3&0xF8)<<8)|((p2&0xFC)<<3)|((p1&0xF8)>>3)];
    src0++; src1++; src2++; src3++; src4++; src5++;
#endif

    /* write the pixel */
    uv = (y1&UVMASK)>>1;
    uv += (y2&UVMASK)>>1;
    uv &= UVMASK;
    y1 &= Y1MASK;
    y2 &= Y2MASK;
    *mydst++ = y1|y2|uv;
  }
}

#undef _6TAP_CLIP
#endif


/**********************************
 * scan2: light 2x2 scanlines
 **********************************/
INLINE void FUNC_NAME(blit_scan2_h_line)(SRC_PIXEL *src, SRC_PIXEL *end,
  unsigned short *dst, int dest_width, unsigned int *lookup)
{
  unsigned int y,uv;
  SRC_PIXEL *mysrc;
  unsigned int *mydst = (unsigned int *)dst;

  for(mysrc=src; mysrc<end; mysrc++)
    *mydst++ = GET_YUV_PIXEL(*mysrc);

  mydst = (unsigned int *)(dst + dest_width);
  for(mysrc=src; mysrc<end; mysrc++) {
    y   = uv = GET_YUV_PIXEL(*mysrc);
    y  &= YMASK;
#ifdef LSB_FIRST
    y   = (y*3)>>2;
#else
    y   = (y>>2)*3;
#endif
    y  &= YMASK;
    uv &= UVMASK;
    *mydst++ = y|uv;
  }
}

BLIT_BEGIN(blit_scan2_h)
BLIT_LOOP(blit_scan2_h_line, 2)
BLIT_END

INLINE void FUNC_NAME(blit_scan2_v_line)(SRC_PIXEL *src,
  SRC_PIXEL *end, unsigned short *dst, int dest_width, unsigned int *lookup)
{
  unsigned int y,yuv;
  unsigned int *mydst = (unsigned int *)dst;

  while(src<end) {
    y    = yuv = GET_YUV_PIXEL(*src);
    y   &= Y2MASK;
    y    = (y*3) >> 2;   
    y   &= Y2MASK;
    yuv &= UVMASK|Y1MASK;
    *mydst++ = y|yuv;
    src++;
  }
}

BLIT_BEGIN(blit_scan2_v)
BLIT_LOOP(blit_scan2_v_line, 1)
BLIT_END


/**********************************
 * rgbscan
 **********************************/
INLINE void FUNC_NAME(blit_rgbscan_h_line)(SRC_PIXEL *src,
  SRC_PIXEL *end, unsigned short *dst, int dest_width, unsigned int *lookup)
{
  unsigned int *mydst = (unsigned int *)dst;
  SRC_PIXEL *mysrc;

  for(mysrc=src; mysrc<end; mysrc++)
    *mydst++ = effect_rgb2yuv[RMASK_SEMI(GETPIXEL(*mysrc))];

  mydst = (unsigned int *)(dst + dest_width);
  for(mysrc=src; mysrc<end; mysrc++)
    *mydst++ = effect_rgb2yuv[GMASK_SEMI(GETPIXEL(*mysrc))];

  mydst = (unsigned int *)(dst + 2*dest_width);
  for(mysrc=src; mysrc<end; mysrc++)
    *mydst++ = effect_rgb2yuv[BMASK_SEMI(GETPIXEL(*mysrc))];
}

BLIT_BEGIN(blit_rgbscan_h)
BLIT_LOOP(blit_rgbscan_h_line, 3)
BLIT_END

INLINE void FUNC_NAME(blit_rgbscan_v_line)(SRC_PIXEL *src,
  SRC_PIXEL *end, unsigned short *dst, int dest_width, unsigned int *lookup)
{
  unsigned int p1, p2, uv;
  unsigned int *mydst = (unsigned int *)dst;

  while(src<end)
  {
    p1 = effect_rgb2yuv[RMASK_SEMI(GETPIXEL(*src))];
    p2 = effect_rgb2yuv[GMASK_SEMI(GETPIXEL(*src))];

    uv = (p1&UVMASK)>>1;
    uv += (p2&UVMASK)>>1;
    uv &= UVMASK;
    p1 &= Y1MASK;
    p2 &= Y2MASK;
    *mydst++ = p1|p2|uv;

    p1 = effect_rgb2yuv[BMASK_SEMI(GETPIXEL(*src))]; src++;
    p2 = effect_rgb2yuv[RMASK_SEMI(GETPIXEL(*src))];

    uv = (p1&UVMASK)>>1;
    uv += (p2&UVMASK)>>1;
    uv &= UVMASK;
    p1 &= Y1MASK;
    p2 &= Y2MASK;
    *mydst++ = p1|p2|uv;

    p1 = effect_rgb2yuv[GMASK_SEMI(GETPIXEL(*src))];
    p2 = effect_rgb2yuv[BMASK_SEMI(GETPIXEL(*src))]; src++;

    uv = (p1&UVMASK)>>1;
    uv += (p2&UVMASK)>>1;
    uv &= UVMASK;
    p1 &= Y1MASK;
    p2 &= Y2MASK;
    *mydst++ = p1|p2|uv;
  }
}

BLIT_BEGIN(blit_rgbscan_v)
BLIT_LOOP(blit_rgbscan_v_line, 1)
BLIT_END


/**********************************
 * scan3, YUY2 version
 * The first line is darkened by 25%,
 * the second line is full brightness, and
 * the third line is darkened by 50%. */
INLINE void FUNC_NAME(blit_scan3_h_line)(SRC_PIXEL *src, SRC_PIXEL *end,
  unsigned short *dst, int dest_width, unsigned int *lookup)
{
  unsigned int y,uv;
  SRC_PIXEL *mysrc;
  unsigned int *mydst = (unsigned int *)dst;

  for(mysrc=src; mysrc<end; mysrc++) {
    y   = uv = GET_YUV_PIXEL(*mysrc);
    y  &= YMASK;
#ifdef LSB_FIRST
    y   = (y*3)>>2;
#else
    y   = (y>>2)*3;
#endif
    y  &= YMASK;
    uv &= UVMASK;
    *mydst++ = y|uv;
  }

  mydst = (unsigned int *)(dst + dest_width);
  for(mysrc=src; mysrc<end; mysrc++)
    *mydst++ = GET_YUV_PIXEL(*mysrc);
    
  mydst = (unsigned int *)(dst + 2*dest_width);
  for(mysrc=src; mysrc<end; mysrc++) {
    y   = uv = GET_YUV_PIXEL(*mysrc);
    y  &= YMASK;
    y >>= 1;
    y  &= YMASK;
    uv &= UVMASK;
    *mydst++ = y|uv;
  }
}

BLIT_BEGIN(blit_scan3_h)
BLIT_LOOP(blit_scan3_h_line, 3)
BLIT_END

INLINE void FUNC_NAME(blit_scan3_v_line)(SRC_PIXEL *src, SRC_PIXEL *end,
  unsigned short *dst, int dest_width, unsigned int *lookup)
{
  unsigned int y,y2,y3,uv,uv2;
  unsigned int *mydst = (unsigned int *)dst;

  while (src < end) {
    y = y2 = uv = GET_YUV_PIXEL(*src); src++;
    y  &= Y1MASK;
    y2 &= Y2MASK;
    uv &= UVMASK;
    y3 = y >> 1;
#ifdef LSB_FIRST
    y  = (y*3)>>2;
#else
    y  = (y>>2)*3;
    y  &= Y1MASK;
    y3 &= Y1MASK;
#endif
    *mydst++ = y | y2 | uv;

    y = y2 = uv2 = GET_YUV_PIXEL(*src); src++;
    y   &= Y2MASK;
#ifdef LSB_FIRST
    y    = (y*3)>>2;
#else
    y    = (y>>2)*3;
#endif
    y   &= Y2MASK;
    uv2 &= UVMASK;
    uv >>= 1;
    uv  += (uv2>>1);
    uv  &= UVMASK;
    *mydst++ = y3 | y | uv;
    
    y3   = (y2 & Y2MASK) >> 1;
    y2  &= Y1MASK;
    y3  &= Y2MASK;
    *mydst++ = y2 | y3 | uv2;
  }
}

BLIT_BEGIN(blit_scan3_v)
BLIT_LOOP(blit_scan3_v_line, 1)
BLIT_END


INLINE void FUNC_NAME(blit_fakescan_v_line)(SRC_PIXEL *src, SRC_PIXEL *end,
  unsigned short *dst, int dest_width, unsigned int *lookup)
{
  unsigned int *mydst = (unsigned int *)dst;

  while(src<end)
  {
    *mydst++ = GET_YUV_PIXEL(*src) & (Y1MASK|UVMASK);
    src++;
  }
}

BLIT_BEGIN(blit_fakescan_v)
BLIT_LOOP(blit_fakescan_v_line, 1);
BLIT_END

#endif /* DISABLE_EFFECTS */
