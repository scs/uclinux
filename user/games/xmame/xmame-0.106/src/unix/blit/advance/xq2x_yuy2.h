/* Configuration defines and includes */
#define XQ2X_GETPIXEL(p) YUV_TO_XQ2X_YUV(GET_YUV_PIXEL(p))
#define HQ2X_YUVLOOKUP(p) (p)
#include "xq2x_yuv.h"
#include "xq2x_defs.h"

/* Pixel glue define, so that we can use the advancemame lookup
   tables unmodified. */
#define P(a, b) p_##b##_##a

INLINE void XQ2X_FUNC_NAME(blit_xq2x_line_2x2) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  unsigned short *dst, int dest_width, unsigned int *lookup)
{
  unsigned int *dst0 = (unsigned int *)dst;
  unsigned int *dst1 = (unsigned int *)(dst + dest_width);
  unsigned int uv, p_0_0 = 0, p_0_1 = 0, p_1_0 = 0, p_1_1 = 0;

  XQ2X_LINE_LOOP_BEGIN
    switch(XQ2X_FUNC_NAME(xq2x_make_mask)(c)) {
      #ifdef HQ2X
      #  include "hq2x.dat"
      #else
      #  include "lq2x.dat"
      #endif
    }
#ifdef LSB_FIRST
    uv    = (p_0_0 & XQ2X_UVMASK) << 7;
    uv   += (p_0_1 & XQ2X_UVMASK) << 7;
    uv   &= UVMASK;
    p_0_0 = (p_0_0>>8) & Y1MASK;
    p_0_1 = (p_0_1<<8) & Y2MASK;
    *dst0++ = p_0_0 | p_0_1 | uv;

    uv    = (p_1_0 & XQ2X_UVMASK) << 7;
    uv   += (p_1_1 & XQ2X_UVMASK) << 7;
    uv   &= UVMASK;
    p_1_0 = (p_1_0>>8) & Y1MASK;
    p_1_1 = (p_1_1<<8) & Y2MASK;
    *dst1++ = p_1_0 | p_1_1 | uv;
#else
    uv    = (p_0_0 & UVMASK) >> 1;
    uv   += (p_0_1 & UVMASK) >> 1;
    uv   &= UVMASK;
    p_0_0 = (p_0_0<<16) & Y1MASK;
    p_0_1 = (p_0_1    ) & Y2MASK;
    *dst0++ = p_0_0 | p_0_1 | uv;

    uv    = (p_1_0 & UVMASK) >> 1;
    uv   += (p_1_1 & UVMASK) >> 1;
    uv   &= UVMASK;
    p_1_0 = (p_1_0<<16) & Y1MASK;
    p_1_1 = (p_1_1    ) & Y2MASK;
    *dst1++ = p_1_0 | p_1_1 | uv;
#endif
  XQ2X_LINE_LOOP_END
}

INLINE void XQ2X_FUNC_NAME(blit_xq2x_line_3x3) ( SRC_PIXEL *src0,
  SRC_PIXEL *src1, SRC_PIXEL *src2, SRC_PIXEL *end1,
  unsigned short *dst, int dest_width, unsigned int *lookup)
{
  unsigned int *dst0 = (unsigned int *)dst;
  unsigned int *dst1 = (unsigned int *)(dst + dest_width);
  unsigned int *dst2 = (unsigned int *)(dst + 2*dest_width);
  unsigned int p0[6] = { 0, 0, 0, 0, 0, 0 };
  unsigned int p1[6] = { 0, 0, 0, 0, 0, 0 };
  unsigned int p2[6] = { 0, 0, 0, 0, 0, 0 };
  unsigned int c[9], uv;
  
  XQ2X_SQUARE_INIT
  
  while(src1 < end1)
  {
    XQ2X_SQUARE_FILL \
    switch(XQ2X_FUNC_NAME(xq2x_make_mask)(c)) {
      #undef P
      #define P(a, b) p##b[a]
      #ifdef HQ2X
      #  include "hq3x.dat"
      #else
      #  include "lq3x.dat"
      #endif
    }
    src0++;
    src1++;
    src2++;
    
    XQ2X_SQUARE_FILL \
    switch(XQ2X_FUNC_NAME(xq2x_make_mask)(c)) {
      #undef P
      #define P(a, b) p##b[(a)+3]
      #ifdef HQ2X
      #  include "hq3x.dat"
      #else
      #  include "lq3x.dat"
      #endif
    }
    src0++;
    src1++;
    src2++;
    
#ifdef LSB_FIRST
    uv    = (p0[0] & XQ2X_UVMASK) << 7;
    uv   += (p0[1] & XQ2X_UVMASK) << 7;
    uv   &= UVMASK;
    p0[0] = (p0[0]>>8) & Y1MASK;
    p0[1] = (p0[1]<<8) & Y2MASK;
    *dst0++ = p0[0] | p0[1] | uv;

    uv    = (p0[2] & XQ2X_UVMASK) << 7;
    uv   += (p0[3] & XQ2X_UVMASK) << 7;
    uv   &= UVMASK;
    p0[2] = (p0[2]>>8) & Y1MASK;
    p0[3] = (p0[3]<<8) & Y2MASK;
    *dst0++ = p0[2] | p0[3] | uv;

    uv    = (p0[4] & XQ2X_UVMASK) << 7;
    uv   += (p0[5] & XQ2X_UVMASK) << 7;
    uv   &= UVMASK;
    p0[4] = (p0[4]>>8) & Y1MASK;
    p0[5] = (p0[5]<<8) & Y2MASK;
    *dst0++ = p0[4] | p0[5] | uv;

    uv    = (p1[0] & XQ2X_UVMASK) << 7;
    uv   += (p1[1] & XQ2X_UVMASK) << 7;
    uv   &= UVMASK;
    p1[0] = (p1[0]>>8) & Y1MASK;
    p1[1] = (p1[1]<<8) & Y2MASK;
    *dst1++ = p1[0] | p1[1] | uv;

    uv    = (p1[2] & XQ2X_UVMASK) << 7;
    uv   += (p1[3] & XQ2X_UVMASK) << 7;
    uv   &= UVMASK;
    p1[2] = (p1[2]>>8) & Y1MASK;
    p1[3] = (p1[3]<<8) & Y2MASK;
    *dst1++ = p1[2] | p1[3] | uv;

    uv    = (p1[4] & XQ2X_UVMASK) << 7;
    uv   += (p1[5] & XQ2X_UVMASK) << 7;
    uv   &= UVMASK;
    p1[4] = (p1[4]>>8) & Y1MASK;
    p1[5] = (p1[5]<<8) & Y2MASK;
    *dst1++ = p1[4] | p1[5] | uv;

    uv    = (p2[0] & XQ2X_UVMASK) << 7;
    uv   += (p2[1] & XQ2X_UVMASK) << 7;
    uv   &= UVMASK;
    p2[0] = (p2[0]>>8) & Y1MASK;
    p2[1] = (p2[1]<<8) & Y2MASK;
    *dst2++ = p2[0] | p2[1] | uv;

    uv    = (p2[2] & XQ2X_UVMASK) << 7;
    uv   += (p2[3] & XQ2X_UVMASK) << 7;
    uv   &= UVMASK;
    p2[2] = (p2[2]>>8) & Y1MASK;
    p2[3] = (p2[3]<<8) & Y2MASK;
    *dst2++ = p2[2] | p2[3] | uv;

    uv    = (p2[4] & XQ2X_UVMASK) << 7;
    uv   += (p2[5] & XQ2X_UVMASK) << 7;
    uv   &= UVMASK;
    p2[4] = (p2[4]>>8) & Y1MASK;
    p2[5] = (p2[5]<<8) & Y2MASK;
    *dst2++ = p2[4] | p2[5] | uv;

#else

    uv    = (p0[0] & UVMASK) >> 1;
    uv   += (p0[1] & UVMASK) >> 1;
    uv   &= UVMASK;
    p0[0] = (p0[0]<<16) & Y1MASK;
    p0[1] = (p0[1]    ) & Y2MASK;
    *dst0++ = p0[0] | p0[1] | uv;

    uv    = (p0[2] & UVMASK) >> 1;
    uv   += (p0[3] & UVMASK) >> 1;
    uv   &= UVMASK;
    p0[2] = (p0[2]<<16) & Y1MASK;
    p0[3] = (p0[3]    ) & Y2MASK;
    *dst0++ = p0[2] | p0[3] | uv;

    uv    = (p0[4] & UVMASK) >> 1;
    uv   += (p0[5] & UVMASK) >> 1;
    uv   &= UVMASK;
    p0[4] = (p0[4]<<16) & Y1MASK;
    p0[5] = (p0[5]    ) & Y2MASK;
    *dst0++ = p0[4] | p0[5] | uv;

    uv    = (p1[0] & UVMASK) >> 1;
    uv   += (p1[1] & UVMASK) >> 1;
    uv   &= UVMASK;
    p1[0] = (p1[0]<<16) & Y1MASK;
    p1[1] = (p1[1]    ) & Y2MASK;
    *dst1++ = p1[0] | p1[1] | uv;

    uv    = (p1[2] & UVMASK) >> 1;
    uv   += (p1[3] & UVMASK) >> 1;
    uv   &= UVMASK;
    p1[2] = (p1[2]<<16) & Y1MASK;
    p1[3] = (p1[3]    ) & Y2MASK;
    *dst1++ = p1[2] | p1[3] | uv;

    uv    = (p1[4] & UVMASK) >> 1;
    uv   += (p1[5] & UVMASK) >> 1;
    uv   &= UVMASK;
    p1[4] = (p1[4]<<16) & Y1MASK;
    p1[5] = (p1[5]    ) & Y2MASK;
    *dst1++ = p1[4] | p1[5] | uv;

    uv    = (p2[0] & UVMASK) >> 1;
    uv   += (p2[1] & UVMASK) >> 1;
    uv   &= UVMASK;
    p2[0] = (p2[0]<<16) & Y1MASK;
    p2[1] = (p2[1]    ) & Y2MASK;
    *dst2++ = p2[0] | p2[1] | uv;

    uv    = (p2[2] & UVMASK) >> 1;
    uv   += (p2[3] & UVMASK) >> 1;
    uv   &= UVMASK;
    p2[2] = (p2[2]<<16) & Y1MASK;
    p2[3] = (p2[3]    ) & Y2MASK;
    *dst2++ = p2[2] | p2[3] | uv;

    uv    = (p2[4] & UVMASK) >> 1;
    uv   += (p2[5] & UVMASK) >> 1;
    uv   &= UVMASK;
    p2[4] = (p2[4]<<16) & Y1MASK;
    p2[5] = (p2[5]    ) & Y2MASK;
    *dst2++ = p2[4] | p2[5] | uv;

#endif
  }
}

#undef P

BLIT_BEGIN(XQ2X_NAME(blit))
  switch(sysdep_display_params.widthscale)
  {
    case 2:
      BLIT_LOOP2X(XQ2X_NAME(blit_xq2x_line_2x2), 2);
      break;
    case 3:
      BLIT_LOOP2X(XQ2X_NAME(blit_xq2x_line_3x3), 3);
      break;
  }
BLIT_END

#include "xq2x_undefs.h"
