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
 */
INLINE void FUNC_NAME(blit_scale2x_border)( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2,
  SRC_PIXEL *end1, unsigned int *dst, unsigned int *lookup)
{
  unsigned int p1,p2,uv;
  while (src1 < end1) {
    if (src1[-1] == src0[0] && src2[0] != src0[0] && src1[1] != src0[0])
      p1 = GET_YUV_PIXEL(src0[0]);
    else p1 = GET_YUV_PIXEL(src1[0]);

    if (src1[1] == src0[0] && src2[0] != src0[0] && src1[-1] != src0[0])
      p2 = GET_YUV_PIXEL(src0[0]);
    else p2 = GET_YUV_PIXEL(src1[0]);

    ++src0;
    ++src1;
    ++src2;

    uv = (p1&UVMASK)>>1;
    uv += (p2&UVMASK)>>1;
    uv &= UVMASK;
    p1 &= Y1MASK;
    p2 &= Y2MASK;
    *dst++ = p1|p2|uv;
  }
}

INLINE void FUNC_NAME(blit_scale2x_line)(SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  unsigned short *dst, int dest_width, unsigned int *lookup)
{
  FUNC_NAME(blit_scale2x_border)(src0, src1, src2, end1,
    (unsigned int *)dst, lookup);
  FUNC_NAME(blit_scale2x_border)(src2, src1, src0, end1,
    (unsigned int *)(dst + dest_width), lookup);
}

INLINE void FUNC_NAME(blit_scale3x_border)( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2,
  SRC_PIXEL *end1, unsigned int *dst, unsigned int *lookup)
{
  unsigned int p1,p2,p3,p4,p5,p6,uv;
  while (src1 < end1) {
    if (src0[0] != src2[0] && src1[-1] != src1[1]) {
    	p1 = GET_YUV_PIXEL(src1[-1] == src0[0] ? src1[-1] : src1[0]);
    	p2 = GET_YUV_PIXEL((src1[-1] == src0[0] && src1[0] != src0[1]) || (src1[1] == src0[0] && src1[0] != src0[-1]) ? src0[0] : src1[0]);
    	p3 = GET_YUV_PIXEL(src1[1] == src0[0] ? src1[1] : src1[0]);
    } else {
    	p1 = p2 = p3 = GET_YUV_PIXEL(src1[0]);
    }
    src0++;
    src1++;
    src2++;
    if (src0[0] != src2[0] && src1[-1] != src1[1]) {
    	p4 = GET_YUV_PIXEL(src1[-1] == src0[0] ? src1[-1] : src1[0]);
    	p5 = GET_YUV_PIXEL((src1[-1] == src0[0] && src1[0] != src0[1]) || (src1[1] == src0[0] && src1[0] != src0[-1]) ? src0[0] : src1[0]);
    	p6 = GET_YUV_PIXEL(src1[1] == src0[0] ? src1[1] : src1[0]);
    } else {
    	p4 = p5 = p6 = GET_YUV_PIXEL(src1[0]);
    }
    src0++;
    src1++;
    src2++;

    uv = (p1&UVMASK)>>1;
    uv += (p2&UVMASK)>>1;
    uv &= UVMASK;
    p1 &= Y1MASK;
    p2 &= Y2MASK;
    *dst++ = p1|p2|uv;


    uv = (p3&UVMASK)>>1;
    uv += (p4&UVMASK)>>1;
    uv &= UVMASK;
    p3 &= Y1MASK;
    p4 &= Y2MASK;
    *dst++ = p3|p4|uv;

    uv = (p5&UVMASK)>>1;
    uv += (p6&UVMASK)>>1;
    uv &= UVMASK;
    p5 &= Y1MASK;
    p6 &= Y2MASK;
    *dst++ = p5|p6|uv;
  }
}

INLINE void FUNC_NAME(blit_scale3x_center)( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2,
  SRC_PIXEL *end1, unsigned int *dst, unsigned int *lookup)
{
  unsigned int p1,p2,p3,p4,p5,p6,uv;
  while (src1 < end1) {
    if (src0[0] != src2[0] && src1[-1] != src1[1]) {
    	p1 = GET_YUV_PIXEL((src1[-1] == src0[0] && src1[0] != src2[-1]) || (src1[-1] == src2[0] && src1[0] != src0[-1]) ? src1[-1] : src1[0]);
    	p2 = GET_YUV_PIXEL(src1[0]);
    	p3 = GET_YUV_PIXEL((src1[1] == src0[0] && src1[0] != src2[1]) || (src1[1] == src2[0] && src1[0] != src0[1]) ? src1[1] : src1[0]);
    } else {
    	p1 = p2 = p3 = GET_YUV_PIXEL(src1[0]);
    }
    src0++;
    src1++;
    src2++;
    if (src0[0] != src2[0] && src1[-1] != src1[1]) {
    	p4 = GET_YUV_PIXEL((src1[-1] == src0[0] && src1[0] != src2[-1]) || (src1[-1] == src2[0] && src1[0] != src0[-1]) ? src1[-1] : src1[0]);
    	p5 = GET_YUV_PIXEL(src1[0]);
    	p6 = GET_YUV_PIXEL((src1[1] == src0[0] && src1[0] != src2[1]) || (src1[1] == src2[0] && src1[0] != src0[1]) ? src1[1] : src1[0]);
    } else {
    	p4 = p5 = p6 = GET_YUV_PIXEL(src1[0]);
    }
    src0++;
    src1++;
    src2++;

    uv = (p1&UVMASK)>>1;
    uv += (p2&UVMASK)>>1;
    uv &= UVMASK;
    p1 &= Y1MASK;
    p2 &= Y2MASK;
    *dst++ = p1|p2|uv;


    uv = (p3&UVMASK)>>1;
    uv += (p4&UVMASK)>>1;
    uv &= UVMASK;
    p3 &= Y1MASK;
    p4 &= Y2MASK;
    *dst++ = p3|p4|uv;

    uv = (p5&UVMASK)>>1;
    uv += (p6&UVMASK)>>1;
    uv &= UVMASK;
    p5 &= Y1MASK;
    p6 &= Y2MASK;
    *dst++ = p5|p6|uv;
  }
}

INLINE void FUNC_NAME(blit_scale3x_line)(SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  unsigned short *dst, int dest_width, unsigned int *lookup)
{
  FUNC_NAME(blit_scale3x_border)(src0, src1, src2, end1,
    (unsigned int *)dst, lookup);
  FUNC_NAME(blit_scale3x_center)(src0, src1, src2, end1,
    (unsigned int *)(dst + dest_width), lookup);
  FUNC_NAME(blit_scale3x_border)(src2, src1, src0, end1,
    (unsigned int *)(dst + 2*dest_width), lookup);
}

BLIT_BEGIN(blit_scale2x)
  switch(sysdep_display_params.widthscale)
  {
    case 2:
      BLIT_LOOP2X(blit_scale2x_line, 2)
      break;
    case 3:
      BLIT_LOOP2X(blit_scale3x_line, 3)
      break;
  }
BLIT_END
