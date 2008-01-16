#include "blit.h"

#define FUNC_NAME(name) name##_32_32_direct
#define SRC_DEPTH  32
#define DEST_DEPTH 32
#include "blit_defs.h"
#include "blit_normal.h"
#ifndef DISABLE_EFFECTS
#include "blit_effect.h"
#include "blit_6tap.h"
#include "advance/scale2x.h"
#include "advance/xq2x.h"
#define HQ2X
#include "advance/xq2x.h"
#endif
#include "blit_undefs.h"
