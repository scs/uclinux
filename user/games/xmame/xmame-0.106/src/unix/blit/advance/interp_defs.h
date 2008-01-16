/* we use GETPIXEL to get the pixels, GETPIXEL should return a pixel
   of RENDER_DEPTH, so all operations we do should be based on RENDER_DEPTH */
#if RENDER_DEPTH == 32 || defined RENDER_YUY2
#define INTERP_16_MASK_1(v) ((v) & 0xFF00FF)
#define INTERP_16_MASK_2(v) ((v) & 0x00FF00)
#define INTERP_16_UNMASK_1(v) ((v) & 0xFF00FF)
#define INTERP_16_UNMASK_2(v) ((v) & 0x00FF00)
#define INTERP_16_HNMASK (~0x808080)
#define interp_uint16 unsigned int
#elif RENDER_DEPTH == 15
#define INTERP_16_MASK_1(v) ((v) & 0x7C1F)
#define INTERP_16_MASK_2(v) ((v) & 0x03E0)
#define INTERP_16_UNMASK_1(v) ((v) & 0x7C1F)
#define INTERP_16_UNMASK_2(v) ((v) & 0x03E0)
#define INTERP_16_HNMASK (~0x4210)
#define interp_uint16 unsigned short
#elif RENDER_DEPTH == 16
#define INTERP_16_MASK_1(v) ((v) & 0xF81F)
#define INTERP_16_MASK_2(v) ((v) & 0x07E0)
#define INTERP_16_UNMASK_1(v) ((v) & 0xF81F)
#define INTERP_16_UNMASK_2(v) ((v) & 0x07E0)
#define INTERP_16_HNMASK (~0x8410)
#define interp_uint16 unsigned short
#endif

#include "interp.h"

#define I1(p0) c[p0]
#define I2(i0, i1, p0, p1) interp_16_##i0##i1(c[p0], c[p1])
#define I3(i0, i1, i2, p0, p1, p2) interp_16_##i0##i1##i2(c[p0], c[p1], c[p2])
