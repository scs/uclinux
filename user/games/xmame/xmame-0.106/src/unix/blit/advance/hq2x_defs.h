#define XQ2X_NAME(x) x##_hq2x
#define XQ2X_FUNC_NAME(x) FUNC_NAME(x##_hq2x)

/* Some glue defines, so that we can use the advancemame lookup
   tables unmodified. */
#define MUR FUNC_NAME(hq2x_is_distant)(c[1], c[5])
#define MDR FUNC_NAME(hq2x_is_distant)(c[5], c[7])
#define MDL FUNC_NAME(hq2x_is_distant)(c[7], c[3])
#define MUL FUNC_NAME(hq2x_is_distant)(c[3], c[1])

/* 2 variants of the is_distant function and mask making code */
#if RENDER_DEPTH != 32
#include "xq2x_yuv.h"

INLINE int FUNC_NAME(hq2x_is_distant)(interp_uint16 w1, interp_uint16 w2)
{
  int yuv1, yuv2;

  yuv1 = HQ2X_YUVLOOKUP(w1);
  yuv2 = HQ2X_YUVLOOKUP(w2);
  return ( ( ((yuv1 & XQ2X_YMASK) - (yuv2 & XQ2X_YMASK)) >  XQ2X_TR_Y ) ||
           ( ((yuv1 & XQ2X_YMASK) - (yuv2 & XQ2X_YMASK)) < -XQ2X_TR_Y ) ||
           ( ((yuv1 & XQ2X_UMASK) - (yuv2 & XQ2X_UMASK)) >  XQ2X_TR_U ) ||
           ( ((yuv1 & XQ2X_UMASK) - (yuv2 & XQ2X_UMASK)) < -XQ2X_TR_U ) ||
           ( ((yuv1 & XQ2X_VMASK) - (yuv2 & XQ2X_VMASK)) >  XQ2X_TR_V ) ||
           ( ((yuv1 & XQ2X_VMASK) - (yuv2 & XQ2X_VMASK)) < -XQ2X_TR_V ) );
}

INLINE unsigned char XQ2X_FUNC_NAME(xq2x_make_mask)(interp_uint16 *c)
{
  int i, y, u, v, yuv;
  unsigned char mask = 0;

  i = HQ2X_YUVLOOKUP(c[4]);
  y = i & XQ2X_YMASK;
  u = i & XQ2X_UMASK;
  v = i & XQ2X_VMASK;
  
  for ( i = 0; i <= 8; i++ )
  {
    if ( i == 4 )
      continue;
    mask >>= 1;
    yuv = HQ2X_YUVLOOKUP(c[i]);
    if ( ( (y - (yuv & XQ2X_YMASK)) >  XQ2X_TR_Y ) ||
         ( (y - (yuv & XQ2X_YMASK)) < -XQ2X_TR_Y ) ||
         ( (u - (yuv & XQ2X_UMASK)) >  XQ2X_TR_U ) ||
         ( (u - (yuv & XQ2X_UMASK)) < -XQ2X_TR_U ) ||
         ( (v - (yuv & XQ2X_VMASK)) >  XQ2X_TR_V ) ||
         ( (v - (yuv & XQ2X_VMASK)) < -XQ2X_TR_V ) )
      mask |= 0x80;
  }
  return mask;
}

#else /* RENDER_DEPTH != 32 */

INLINE int FUNC_NAME(hq2x_is_distant)(interp_uint16 w1, interp_uint16 w2)
{
  int r1, g1, b1, r2, g2, b2;

  r1 = RMASK(w1) >> 16;
  g1 = GMASK(w1) >> 8;
  b1 = BMASK(w1);
  r2 = RMASK(w2) >> 16;
  g2 = GMASK(w2) >> 8;
  b2 = BMASK(w2);

  return ( ( ( (r1+g1+b1) - (r2+g2+b2) )    >  0xC0 ) ||
           ( ( (r1+g1+b1) - (r2+g2+b2) )    < -0xC0 ) ||
           ( ( (r1-b1)    - (r2-b2)    )    >  0x1C ) ||
           ( ( (r1-b1)    - (r2-b2)    )    < -0x1C ) ||
           ( ( (-r1+2*g1-b1) - (-r2+2*g2-b2) ) >  0x18 ) ||
           ( ( (-r1+2*g1-b1) - (-r2+2*g2-b2) ) < -0x18 ) );
}

INLINE unsigned char XQ2X_FUNC_NAME(xq2x_make_mask)(interp_uint16 *c)
{
  int i, r, g, b, y, u, v;
  unsigned char mask = 0;
  
  r = RMASK(c[4]) >> 16;
  g = GMASK(c[4]) >> 8;
  b = BMASK(c[4]);
  y = r+g+b;
  u = r-b;
  v = -r+2*g-b;
  
  for ( i = 0; i <= 8; i++ )
  {
    if ( i == 4 )
      continue;
    mask >>= 1;
    r = RMASK(c[i]) >> 16;
    g = GMASK(c[i]) >> 8;
    b = BMASK(c[i]);
    if ( ( (y - (r+g+b) )    >  0xC0 ) ||
         ( (y - (r+g+b) )    < -0xC0 ) ||
         ( (u - (r-b)    )   >  0x1C ) ||
         ( (u - (r-b)    )   < -0x1C ) ||
         ( (v - (-r+2*g-b) ) >  0x18 ) ||
         ( (v - (-r+2*g-b) ) < -0x18 ) )
      mask |= 0x80;
  }
  return mask;
}

#endif /* RENDER_DEPTH != 32 */
