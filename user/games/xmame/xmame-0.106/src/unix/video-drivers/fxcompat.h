#ifndef __FXCOMPAT_H
#define __FXCOMPAT_H

#include <glide.h>

/* detect Glide version 3 instead of version 2 */
#ifdef GR_ASPECT_LOG2_8x1
/* Glide version 3 */

/*
** move the vertex layout defintion to application
*/
typedef struct {
  float  sow;                   /* s texture ordinate (s over w) */
  float  tow;                   /* t texture ordinate (t over w) */
  float  oow;                   /* 1/w (used mipmapping - really 0xfff/w) */
}  GrTmuVertex;

typedef struct
{
  float x, y;         /* X and Y in screen space */
  float ooz;          /* 65535/Z (used for Z-buffering) */
  float oow;          /* 1/W (used for W-buffering, texturing) */
  float r, g, b, a;   /* R, G, B, A [0..255.0] */
  float z;            /* Z is ignored */
  GrTmuVertex  tmuvtx[GLIDE_NUM_TMU];
} GrVertex;

#define GR_VERTEX_X_OFFSET              0
#define GR_VERTEX_Y_OFFSET              1
#define GR_VERTEX_OOZ_OFFSET            2
#define GR_VERTEX_OOW_OFFSET            3
#define GR_VERTEX_R_OFFSET              4
#define GR_VERTEX_G_OFFSET              5
#define GR_VERTEX_B_OFFSET              6
#define GR_VERTEX_A_OFFSET              7
#define GR_VERTEX_Z_OFFSET              8
#define GR_VERTEX_SOW_TMU0_OFFSET       9
#define GR_VERTEX_TOW_TMU0_OFFSET       10
#define GR_VERTEX_OOW_TMU0_OFFSET       11
#define GR_VERTEX_SOW_TMU1_OFFSET       12
#define GR_VERTEX_TOW_TMU1_OFFSET       13
#define GR_VERTEX_OOW_TMU1_OFFSET       14

#define grSetupVertexLayout() \
  grVertexLayout(GR_PARAM_XY,  GR_VERTEX_X_OFFSET << 2, GR_PARAM_ENABLE); \
  grVertexLayout(GR_PARAM_RGB, GR_VERTEX_R_OFFSET << 2, GR_PARAM_ENABLE); \
  grVertexLayout(GR_PARAM_A,   GR_VERTEX_A_OFFSET << 2, GR_PARAM_ENABLE); \
  grVertexLayout(GR_PARAM_Q,   GR_VERTEX_OOW_OFFSET << 2, GR_PARAM_ENABLE); \
  grVertexLayout(GR_PARAM_ST0, GR_VERTEX_SOW_TMU0_OFFSET << 2, GR_PARAM_ENABLE);

/* these work inverted as one would expect */
#define grEnablePassThru()  grDisable(GR_PASSTHRU)
#define grDisablePassThru() grEnable(GR_PASSTHRU)
#define grEnableAA()        grEnable(GR_AA_ORDERED)
#define grDisableAA()       grDisable(GR_AA_ORDERED)
#define grSstCloseWin(C)    grSstWinClose(C)

#define GR_LOD_256 GR_LOD_LOG2_256
#define GR_ASPECT_1x1 GR_ASPECT_LOG2_1x1
#define smallLod smallLodLog2
#define largeLod largeLodLog2
#define aspectRatio aspectRatioLog2
#define grAADrawLine grDrawLine
#define grAADrawPoint grDrawPoint

#include <string.h>

#define grGlideGetVersion(version)					\
{									\
   const char *v;							\
   v = grGetString( GR_VERSION );					\
   strcpy(version, v);							\
}

#define grGlideGetNumBoards(num_boards_pt)                              \
{                                                                       \
   FxI32 num_sst;                                                       \
   if(grGet(GR_NUM_BOARDS, sizeof(FxI32), &num_sst) == sizeof(FxI32))   \
     *(num_boards_pt) = num_sst;                                        \
   else                                                                 \
     *(num_boards_pt) = 0;                                              \
}
#else
/* Glide version 2 */

#define grSetupVertexLayout()
#define grEnablePassThru()  grSstControl(GR_CONTROL_DEACTIVATE)
#define grDisablePassThru() grSstControl(GR_CONTROL_ACTIVATE)
#define grEnableAA()
#define grDisableAA()
#define grSstCloseWin(C)    grSstWinClose()

#define GrContext_t FxBool

#define grGlideGetNumBoards(num_boards_pt)                              \
{                                                                       \
   GrHwConfiguration hwconfig;                                          \
   grSstQueryHardware(&hwconfig);                                       \
   *(num_boards_pt) = hwconfig.num_sst;                                 \
}

#endif

#endif /* __FXCOMPAT_H */
