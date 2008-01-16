#include "pixel_defs.h"
#include "blit.h"

#define FUNC_NAME(name) name##_16_YUY2
#define SRC_DEPTH    16
#define DEST_DEPTH   16
#define RENDER_YUY2
#define GET_YUV_PIXEL(p) lookup[p]
#include "blit_defs.h"
#include "blit_yuy2.h"
#ifndef DISABLE_EFFECTS
#include "blit_6tap.h"
#include "advance/scale2x_yuy2.h"
#include "advance/xq2x_yuy2.h"
#define HQ2X
#include "advance/xq2x_yuy2.h"
#endif
#include "blit_undefs.h"
