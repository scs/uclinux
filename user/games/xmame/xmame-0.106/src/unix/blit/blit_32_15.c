#include "pixel_defs.h"
#include "blit.h"

/* normal blitting and 6tap converts the pixels while blitting */
#define FUNC_NAME(name) name##_32_15_direct
#define SRC_DEPTH    32
#define DEST_DEPTH   15
#include "blit_defs.h"
#include "blit_normal.h"
#ifndef DISABLE_EFFECTS
#include "blit_6tap.h"
#include "blit_undefs.h"

/* Effects can also convert the pixels at the fly (through the GETPIXEL macro)
   which should be faster (and is somewhat faster on an Athlon) since we only
   have to loop once then. But on intel's sucky P4 this is much slower then
   first rendering to an intermediate 32 bpp sparse buffer and then converting
   this buffer and blitted it to the final destination by this function: */
INLINE void blit_line_32_15(unsigned int *src, unsigned int *end, unsigned short *dst)
{
  for(;src<end; src+=4,dst+=4)
  {
    *(dst  ) = _32TO16_RGB_555(*(src  ));
    *(dst+1) = _32TO16_RGB_555(*(src+1));
    *(dst+2) = _32TO16_RGB_555(*(src+2));
    *(dst+3) = _32TO16_RGB_555(*(src+3));
  }
}

#define FUNC_NAME(name) name##_32_15_direct
#define SRC_DEPTH    32
#define DEST_DEPTH   15
#define RENDER_DEPTH 32
#define BLIT_LINE_FUNC blit_line_32_15
#include "blit_defs.h"
#include "blit_effect.h"
#include "advance/scale2x.h"
#include "advance/xq2x.h"
#define HQ2X
#include "advance/xq2x.h"
#endif
#include "blit_undefs.h"
