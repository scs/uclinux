#include "blit.h"

#define FUNC_NAME(name) name##_16_32
#define SRC_DEPTH  16
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
#include "blit_undefs.h"
#endif
