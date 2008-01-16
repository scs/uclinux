#include "interp_undefs.h"

#undef XQ2X_NAME
#undef XQ2X_FUNC_NAME

#undef MUR
#undef MDR
#undef MDL
#undef MUL

#undef XQ2X_SQUARE_INIT
#undef XQ2X_SQUARE_FILL
#undef XQ2X_LINE_LOOP_BEGIN 

#undef XQ2X_SQUARE_INIT_SWAP_XY
#undef XQ2X_SQUARE_FILL_SWAP_XY
#undef XQ2X_LINE_LOOP_BEGIN_SWAP_XY

#undef XQ2X_LINE_LOOP_END

/* this saves us from having to undef these each time in the files using
   the blit macros */
#undef XQ2X_GETPIXEL
#undef HQ2X_YUVLOOKUP
