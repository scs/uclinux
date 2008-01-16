#include "interp_defs.h"
#ifdef HQ2X
#  include "hq2x_defs.h"
#else
#  include "lq2x_defs.h"
#endif

#define XQ2X_SQUARE_INIT \
  c[1] = XQ2X_GETPIXEL(src0[-1]); \
  c[2] = XQ2X_GETPIXEL(src0[ 0]); \
  c[4] = XQ2X_GETPIXEL(src1[-1]); \
  c[5] = XQ2X_GETPIXEL(src1[ 0]); \
  c[7] = XQ2X_GETPIXEL(src2[-1]); \
  c[8] = XQ2X_GETPIXEL(src2[ 0]);

#define XQ2X_SQUARE_FILL \
  c[0] = c[1]; \
  c[1] = c[2]; \
  c[2] = XQ2X_GETPIXEL(src0[1]); \
  c[3] = c[4]; \
  c[4] = c[5]; \
  c[5] = XQ2X_GETPIXEL(src1[1]); \
  c[6] = c[7]; \
  c[7] = c[8]; \
  c[8] = XQ2X_GETPIXEL(src2[1]);

#define XQ2X_LINE_LOOP_BEGIN \
  interp_uint16 c[9]; \
  \
  XQ2X_SQUARE_INIT \
  \
  while(src1 < end1) \
  { \
    XQ2X_SQUARE_FILL


#define XQ2X_SQUARE_INIT_SWAP_XY \
  c[3] = XQ2X_GETPIXEL(src0[-1]); \
  c[4] = XQ2X_GETPIXEL(src1[-1]); \
  c[5] = XQ2X_GETPIXEL(src2[-1]); \
  c[6] = XQ2X_GETPIXEL(src0[0]); \
  c[7] = XQ2X_GETPIXEL(src1[0]); \
  c[8] = XQ2X_GETPIXEL(src2[0]);

#define XQ2X_SQUARE_FILL_SWAP_XY \
  c[0] = c[3]; \
  c[1] = c[4]; \
  c[2] = c[5]; \
  c[3] = c[6]; \
  c[4] = c[7]; \
  c[5] = c[8]; \
  c[6] = XQ2X_GETPIXEL(src0[1]); \
  c[7] = XQ2X_GETPIXEL(src1[1]); \
  c[8] = XQ2X_GETPIXEL(src2[1]);

#define XQ2X_LINE_LOOP_BEGIN_SWAP_XY \
  interp_uint16 c[9]; \
  \
  XQ2X_SQUARE_INIT_SWAP_XY \
  \
  while(src1 < end1) \
  { \
    XQ2X_SQUARE_FILL_SWAP_XY


#define XQ2X_LINE_LOOP_END \
    src0++; \
    src1++; \
    src2++; \
  }
