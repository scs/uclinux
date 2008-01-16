#include "blit.h"

/* As you may notice we don't include "blit_normal.h" and "scale2x.h", thats
   because these don't do any calculations with pixels and thus there
   is no difference between the 16_15 and 16_16 versions. */
#define FUNC_NAME(name) name##_16_15
#define SRC_DEPTH  16
#define DEST_DEPTH 15
#include "blit_defs.h"
#ifndef DISABLE_EFFECTS
#include "blit_effect.h"
#include "blit_6tap.h"
#include "advance/xq2x.h"
#define HQ2X
#include "advance/xq2x.h"
#endif
#include "blit_undefs.h"
