#include "blit.h"

#define FUNC_NAME(name) name##_15_15_direct
#define SRC_DEPTH  15
#define DEST_DEPTH 15
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
