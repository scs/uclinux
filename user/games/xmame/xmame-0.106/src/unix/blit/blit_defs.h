#include <string.h>
#include "effect.h"
#include "pixel_defs.h"

#ifndef RENDER_DEPTH
#  define RENDER_DEPTH DEST_DEPTH
#endif

#if SRC_DEPTH == 15
#  define SRC_PIXEL unsigned short
#  define GETPIXEL(p) p
#elif SRC_DEPTH == 16
#  define SRC_PIXEL unsigned short
#  define GETPIXEL(p) lookup[p]
#elif SRC_DEPTH == 32
#  define SRC_PIXEL unsigned int
#  if RENDER_DEPTH == 15
#    define GETPIXEL(p) _32TO16_RGB_555(p)
#  elif RENDER_DEPTH == 16
#    define GETPIXEL(p) _32TO16_RGB_565(p)
#  elif DEST_DEPTH == 24
     /* When blitting from a 32 bpp src to a 24 bpp dest the source bitmap
        might have cruft the msb of the sparse 32 bpp pixels (artwork), so in
        this case we need to mask out the msb */
#    define GETPIXEL(p) ((p)&0x00FFFFFF)
#  else
#    define GETPIXEL(p) p
#  endif
#else
#  error Unknown SRC_DEPTH
#endif

#if RENDER_DEPTH == 15
#  define RMASK(P) ((P) & 0x7c00)
#  define GMASK(P) ((P) & 0x03e0)
#  define BMASK(P) ((P) & 0x001f)
#  define RMASK_INV_HALF(P) (((P)>>1) & 0x01ef)
#  define GMASK_INV_HALF(P) (((P)>>1) & 0x3c0f)
#  define BMASK_INV_HALF(P) (((P)>>1) & 0x3de0)
#  define SHADE_HALF(P)   (((P)>>1) & 0x3def)
#  define SHADE_FOURTH(P) (((P)>>2) & 0x1ce7)
#  define RENDER_PIXEL unsigned short
#  define RGB_TO_RENDER_PIXEL(r,g,b) ((((r)&0xf8)<<7)|(((g)&0xf8)<<2)|(((b)&0xf8)>>3))
#  define RGB32_TO_RENDER_PIXEL(rgb) ((((rgb)&0xf80000)>>9)|(((rgb)&0xf800)>>6)|(((rgb)&0xf8)>>3))
#elif RENDER_DEPTH == 16
#  define RMASK(P) ((P) & 0xf800)
#  define GMASK(P) ((P) & 0x07e0)
#  define BMASK(P) ((P) & 0x001f)
#  define RMASK_INV_HALF(P) (((P)>>1) & 0x03ef)
#  define GMASK_INV_HALF(P) (((P)>>1) & 0x780f)
#  define BMASK_INV_HALF(P) (((P)>>1) & 0xebe0)
#  define SHADE_HALF(P)   (((P)>>1) & 0x7bef)
#  define SHADE_FOURTH(P) (((P)>>2) & 0x39e7)
#  define RENDER_PIXEL unsigned short
#  define RGB_TO_RENDER_PIXEL(r,g,b) ((((r)&0xf8)<<8)|(((g)&0xfc)<<3)|(((b)&0xf8)>>3))
#  define RGB32_TO_RENDER_PIXEL(rgb) ((((rgb)&0xf80000)>>8)|(((rgb)&0x00fc00)>>5)|(((rgb)&0x0000f8)>>3))
#elif RENDER_DEPTH == 32
#  define RMASK(P) ((P) & 0x00ff0000)
#  define GMASK(P) ((P) & 0x0000ff00)
#  define BMASK(P) ((P) & 0x000000ff)
#  define RMASK_INV_HALF(P) (((P)>>1) & 0x00007f7f)
#  define GMASK_INV_HALF(P) (((P)>>1) & 0x007f007f)
#  define BMASK_INV_HALF(P) (((P)>>1) & 0x007f7f00)
#  define SHADE_HALF(P)   (((P)>>1) & 0x007f7f7f)
#  define SHADE_FOURTH(P) (((P)>>2) & 0x003f3f3f)
#  define RENDER_PIXEL unsigned int
#  define RGB_TO_RENDER_PIXEL(r,g,b) (((r)<<16)|((g)<<8)|(b))
#  define RGB32_TO_RENDER_PIXEL(rgb) (rgb)
#else
#  error Unknown RENDER_DEPTH
#endif

#if (DEST_DEPTH == 15) || (DEST_DEPTH == 16)
#  define DEST_PIXEL unsigned short
#  define DEST_PIXEL_SIZE 2
#  define DEST_WIDTH dest_width
#elif DEST_DEPTH == 24
#  define DEST_PIXEL unsigned int
#  define DEST_PIXEL_SIZE 3
#  define DEST_WIDTH ((dest_width*3)/4)
#elif DEST_DEPTH == 32
#  define DEST_PIXEL unsigned int
#  define DEST_PIXEL_SIZE 4
#  define DEST_WIDTH dest_width
#else
#  error Unknown DEST_DEPTH
#endif

#ifdef BLIT_LINE_FUNC
#define RENDER_WIDTH (vis_in_dest_out->max_x - vis_in_dest_out->min_x)
#define RENDER_DEST  effect_dbbuf
#define BLIT_LINE(Y) \
  { \
    int y=Y; \
    RENDER_PIXEL *src = (RENDER_PIXEL *)(effect_dbbuf); \
    while(y) \
    { \
      BLIT_LINE_FUNC(src, src+RENDER_WIDTH, line_dest); \
      src += RENDER_WIDTH; \
      line_dest += DEST_WIDTH; \
      y--; \
    } \
  }
#else
#define RENDER_WIDTH dest_width
#define RENDER_DEST  line_dest
#define BLIT_LINE(Y) line_dest+=Y*DEST_WIDTH;
#endif

#define BLIT_BEGIN(NAME) \
void FUNC_NAME(NAME)(mame_bitmap *bitmap, \
  rectangle *vis_in_dest_out, rectangle *dirty_area, \
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width) \
{ \
  int y, yarbsize; \
  DEST_PIXEL *line_dest; \
  \
  sysdep_display_check_bounds(bitmap, vis_in_dest_out, dirty_area, 3); \
  \
  yarbsize  = sysdep_display_params.yarbsize? \
    sysdep_display_params.yarbsize: \
    sysdep_display_params.height*sysdep_display_params.heightscale; \
  line_dest = (DEST_PIXEL *)(dest + (vis_in_dest_out->min_y*dest_width + \
    vis_in_dest_out->min_x)*DEST_PIXEL_SIZE);

#define BLIT_END \
}

#define BLIT_LOOP(RENDER_LINE, Y) \
  if (sysdep_display_params.orientation) { \
    for (y = dirty_area->min_y; y < dirty_area->max_y; y++) \
    { \
      rotate_func(rotate_dbbuf0, bitmap, y, dirty_area); \
      FUNC_NAME(RENDER_LINE)((SRC_PIXEL *)rotate_dbbuf0, \
        (SRC_PIXEL *)rotate_dbbuf0 + (dirty_area->max_x-dirty_area->min_x), \
        (RENDER_PIXEL *)RENDER_DEST, RENDER_WIDTH, palette->lookup); \
      BLIT_LINE(Y) \
    } \
  } else { \
    for (y = dirty_area->min_y; y < dirty_area->max_y; y++) \
    { \
      FUNC_NAME(RENDER_LINE)( \
        (SRC_PIXEL *)(bitmap->line[y]) + dirty_area->min_x, \
        (SRC_PIXEL *)(bitmap->line[y]) + dirty_area->max_x, \
        (RENDER_PIXEL *)RENDER_DEST, RENDER_WIDTH, palette->lookup); \
      BLIT_LINE(Y) \
    } \
  }

#define BLIT_LOOP2X(RENDER_LINE, Y) \
  if (sysdep_display_params.orientation) \
  { \
    char *tmp; \
    /* preload the first lines for 2x effects */ \
    rotate_func(rotate_dbbuf1, bitmap, dirty_area->min_y-1, dirty_area); \
    rotate_func(rotate_dbbuf2, bitmap, dirty_area->min_y, dirty_area); \
    \
    for (y = dirty_area->min_y; y < dirty_area->max_y; y++) { \
      /* shift lines up */ \
      tmp = rotate_dbbuf0; \
      rotate_dbbuf0=rotate_dbbuf1; \
      rotate_dbbuf1=rotate_dbbuf2; \
      rotate_dbbuf2=tmp; \
      rotate_func(rotate_dbbuf2, bitmap, y+1, dirty_area); \
      FUNC_NAME(RENDER_LINE)((SRC_PIXEL *)rotate_dbbuf0, \
        (SRC_PIXEL *)rotate_dbbuf1, (SRC_PIXEL *)rotate_dbbuf2, \
        (SRC_PIXEL *)rotate_dbbuf1 + (dirty_area->max_x-dirty_area->min_x), \
        (RENDER_PIXEL *)RENDER_DEST, RENDER_WIDTH, palette->lookup); \
      BLIT_LINE(Y) \
    } \
  } else { \
    for (y = dirty_area->min_y; y < dirty_area->max_y; y++) { \
      FUNC_NAME(RENDER_LINE)( \
        (SRC_PIXEL *)(bitmap->line[y-1]) + dirty_area->min_x, \
        (SRC_PIXEL *)(bitmap->line[y  ]) + dirty_area->min_x, \
        (SRC_PIXEL *)(bitmap->line[y+1]) + dirty_area->min_x, \
        (SRC_PIXEL *)(bitmap->line[y  ]) + dirty_area->max_x, \
        (RENDER_PIXEL *)RENDER_DEST, RENDER_WIDTH, palette->lookup); \
      BLIT_LINE(Y) \
    } \
  }
  
#ifdef BLIT_LINE_FUNC
#define BLIT_LOOP2X_DFB BLIT_LOOP2X
#else
#define BLIT_LOOP2X_DFB(RENDER_LINE, Y) \
  if (sysdep_display_params.orientation) \
  { \
    char *tmp; \
    int i, blit_width = vis_in_dest_out->max_x - vis_in_dest_out->min_x; \
    /* preload the first lines for 2x effects */ \
    rotate_func(rotate_dbbuf1, bitmap, dirty_area->min_y-1, dirty_area); \
    rotate_func(rotate_dbbuf2, bitmap, dirty_area->min_y, dirty_area); \
    \
    for (y = dirty_area->min_y; y < dirty_area->max_y; y++) { \
      /* shift lines up */ \
      tmp = rotate_dbbuf0; \
      rotate_dbbuf0=rotate_dbbuf1; \
      rotate_dbbuf1=rotate_dbbuf2; \
      rotate_dbbuf2=tmp; \
      rotate_func(rotate_dbbuf2, bitmap, y+1, dirty_area); \
      FUNC_NAME(RENDER_LINE)((SRC_PIXEL *)rotate_dbbuf0, \
        (SRC_PIXEL *)rotate_dbbuf1, (SRC_PIXEL *)rotate_dbbuf2, \
        (SRC_PIXEL *)rotate_dbbuf1 + (dirty_area->max_x-dirty_area->min_x), \
        (RENDER_PIXEL *)effect_dbbuf, blit_width, palette->lookup); \
      for (i=0; i<Y; i++) \
      { \
        memcpy(line_dest, effect_dbbuf + i * blit_width * DEST_PIXEL_SIZE, \
          blit_width * DEST_PIXEL_SIZE); \
        line_dest+=DEST_WIDTH; \
      } \
    } \
  } else { \
    int i, blit_width = vis_in_dest_out->max_x - vis_in_dest_out->min_x; \
    \
    for (y = dirty_area->min_y; y < dirty_area->max_y; y++) { \
      FUNC_NAME(RENDER_LINE)( \
        (SRC_PIXEL *)(bitmap->line[y-1]) + dirty_area->min_x, \
        (SRC_PIXEL *)(bitmap->line[y  ]) + dirty_area->min_x, \
        (SRC_PIXEL *)(bitmap->line[y+1]) + dirty_area->min_x, \
        (SRC_PIXEL *)(bitmap->line[y  ]) + dirty_area->max_x, \
        (RENDER_PIXEL *)effect_dbbuf, blit_width, palette->lookup); \
      for (i=0; i<Y; i++) \
      { \
        memcpy(line_dest, effect_dbbuf + i * blit_width * DEST_PIXEL_SIZE, \
          blit_width * DEST_PIXEL_SIZE); \
        line_dest+=DEST_WIDTH; \
      } \
    } \
  }
#endif
  
#define BLIT_LOOP_YARBSIZE_NORMAL(RENDER_LINE) \
  if (sysdep_display_params.orientation) { \
    for (y = dirty_area->min_y; y < dirty_area->max_y; y++) { \
      /* arbitrary Y-scaling (Adam D. Moss <adam@gimp.org>) */ \
      int reps = ((y+1)*yarbsize)/sysdep_display_params.height - \
        (y*yarbsize)/sysdep_display_params.height; \
      if (reps) { \
        rotate_func(rotate_dbbuf0, bitmap, y, dirty_area); \
        FUNC_NAME(RENDER_LINE)((SRC_PIXEL *)rotate_dbbuf0, \
          (SRC_PIXEL *)rotate_dbbuf0 + (dirty_area->max_x-dirty_area->min_x), \
          (RENDER_PIXEL *)RENDER_DEST, palette->lookup); \
        BLIT_LINE(1) \
        while (--reps) { \
          memcpy(line_dest, line_dest-DEST_WIDTH, \
            (vis_in_dest_out->max_x - vis_in_dest_out->min_x) * \
            DEST_PIXEL_SIZE); \
          line_dest += DEST_WIDTH; \
        } \
      } \
    } \
  } else { \
    for (y = dirty_area->min_y; y < dirty_area->max_y; y++) { \
      int reps = ((y+1)*yarbsize)/sysdep_display_params.height - \
        (y*yarbsize)/sysdep_display_params.height; \
      if (reps) { \
        FUNC_NAME(RENDER_LINE)( \
          ((SRC_PIXEL *)(bitmap->line[y])) + dirty_area->min_x, \
          ((SRC_PIXEL *)(bitmap->line[y])) + dirty_area->max_x, \
          (RENDER_PIXEL *)RENDER_DEST, palette->lookup); \
        BLIT_LINE(1) \
        while (--reps) { \
          memcpy(line_dest, line_dest-DEST_WIDTH, \
            (vis_in_dest_out->max_x - vis_in_dest_out->min_x) * \
            DEST_PIXEL_SIZE); \
          line_dest += DEST_WIDTH; \
        } \
      } \
    } \
  }

#ifdef BLIT_LINE_FUNC /* special BLIT_LINE_FUNC yarbsize DFB case */
#define BLIT_LOOP_YARBSIZE_DFB(RENDER_LINE) \
  if (sysdep_display_params.orientation) { \
    for (y = dirty_area->min_y; y < dirty_area->max_y; y++) { \
      int reps = ((y+1)*yarbsize)/sysdep_display_params.height - \
        (y*yarbsize)/sysdep_display_params.height; \
      if (reps) { \
        rotate_func(rotate_dbbuf0, bitmap, y, dirty_area); \
        FUNC_NAME(RENDER_LINE)((SRC_PIXEL *)rotate_dbbuf0, \
          (SRC_PIXEL *)rotate_dbbuf0 + (dirty_area->max_x-dirty_area->min_x), \
          (RENDER_PIXEL *)effect_dbbuf, palette->lookup); \
        do { \
          BLIT_LINE_FUNC((RENDER_PIXEL *)effect_dbbuf, \
            (RENDER_PIXEL *)effect_dbbuf + vis_in_dest_out->max_x - \
            vis_in_dest_out->min_x, line_dest); \
          line_dest += DEST_WIDTH; \
        } while(--reps); \
      } \
    } \
  } else { \
    for (y = dirty_area->min_y; y < dirty_area->max_y; y++) { \
      int reps = ((y+1)*yarbsize)/sysdep_display_params.height - \
        (y*yarbsize)/sysdep_display_params.height; \
      if (reps) { \
        FUNC_NAME(RENDER_LINE)( \
          ((SRC_PIXEL *)(bitmap->line[y])) + dirty_area->min_x, \
          ((SRC_PIXEL *)(bitmap->line[y])) + dirty_area->max_x, \
          (RENDER_PIXEL *)effect_dbbuf, palette->lookup); \
        do { \
          BLIT_LINE_FUNC((RENDER_PIXEL *)effect_dbbuf, \
            (RENDER_PIXEL *)effect_dbbuf + vis_in_dest_out->max_x - \
            vis_in_dest_out->min_x, line_dest); \
          line_dest += DEST_WIDTH; \
        } while(--reps); \
      } \
    } \
  }
#else
#define BLIT_LOOP_YARBSIZE_DFB(RENDER_LINE) \
  if (sysdep_display_params.orientation) { \
    for (y = dirty_area->min_y; y < dirty_area->max_y; y++) { \
      int reps = ((y+1)*yarbsize)/sysdep_display_params.height - \
        (y*yarbsize)/sysdep_display_params.height; \
      if (reps) { \
        rotate_func(rotate_dbbuf0, bitmap, y, dirty_area); \
        do { \
          FUNC_NAME(RENDER_LINE)((SRC_PIXEL *)rotate_dbbuf0, \
            (SRC_PIXEL *)rotate_dbbuf0 + (dirty_area->max_x-dirty_area->min_x), \
            (DEST_PIXEL *)line_dest, palette->lookup); \
          line_dest += DEST_WIDTH; \
        } while(--reps); \
      } \
    } \
  } else { \
    for (y = dirty_area->min_y; y < dirty_area->max_y; y++) { \
      int reps = ((y+1)*yarbsize)/sysdep_display_params.height - \
        (y*yarbsize)/sysdep_display_params.height; \
      while (reps) { \
        FUNC_NAME(RENDER_LINE)( \
          ((SRC_PIXEL *)(bitmap->line[y])) + dirty_area->min_x, \
          ((SRC_PIXEL *)(bitmap->line[y])) + dirty_area->max_x, \
          (DEST_PIXEL *)line_dest, palette->lookup); \
        line_dest += DEST_WIDTH; \
        reps--; \
      } \
    } \
  }
#endif

#define BLIT_LOOP_YARBSIZE(RENDER_LINE) \
  if (sysdep_display_properties.mode_info[sysdep_display_params.video_mode] & \
      SYSDEP_DISPLAY_DIRECT_FB) \
  { \
    BLIT_LOOP_YARBSIZE_DFB(RENDER_LINE) \
  } else { \
    BLIT_LOOP_YARBSIZE_NORMAL(RENDER_LINE) \
  }

#define BLIT_LOOP_FAKESCAN(BLIT_LINE) \
if (sysdep_display_params.orientation) { \
  if (sysdep_display_properties.mode_info[sysdep_display_params.video_mode] & \
      SYSDEP_DISPLAY_DIRECT_FB) \
  { \
    for (y = dirty_area->min_y; y < dirty_area->max_y; y++) { \
      int reps = sysdep_display_params.heightscale; \
      rotate_func(rotate_dbbuf0, bitmap, y, dirty_area); \
      while (--reps) { \
        FUNC_NAME(BLIT_LINE)((SRC_PIXEL *)rotate_dbbuf0, \
          (SRC_PIXEL *)rotate_dbbuf0 + (dirty_area->max_x-dirty_area->min_x), \
          line_dest, palette->lookup); \
        line_dest += DEST_WIDTH; \
      } \
      line_dest += DEST_WIDTH; \
    } \
  } else { \
    for (y = dirty_area->min_y; y < dirty_area->max_y; y++) { \
      int reps = sysdep_display_params.heightscale-1; \
      rotate_func(rotate_dbbuf0, bitmap, y, dirty_area); \
      FUNC_NAME(BLIT_LINE)((SRC_PIXEL *)rotate_dbbuf0, \
        (SRC_PIXEL *)rotate_dbbuf0 + (dirty_area->max_x-dirty_area->min_x), \
        line_dest, palette->lookup); \
      while (--reps) { \
        memcpy(line_dest+DEST_WIDTH, line_dest, \
          (vis_in_dest_out->max_x-vis_in_dest_out->min_x)*DEST_PIXEL_SIZE); \
        line_dest += DEST_WIDTH; \
      } \
      line_dest += 2*DEST_WIDTH; \
    } \
  } \
} else { \
  if (sysdep_display_properties.mode_info[sysdep_display_params.video_mode] & \
      SYSDEP_DISPLAY_DIRECT_FB) \
  { \
    for (y = dirty_area->min_y; y < dirty_area->max_y; y++) { \
      int reps = sysdep_display_params.heightscale; \
      while (--reps) { \
        FUNC_NAME(BLIT_LINE)( \
          ((SRC_PIXEL *)(bitmap->line[y])) + dirty_area->min_x, \
          ((SRC_PIXEL *)(bitmap->line[y])) + dirty_area->max_x, \
          line_dest, palette->lookup); \
        line_dest += DEST_WIDTH; \
      } \
      line_dest += DEST_WIDTH; \
    } \
  } else { \
    for (y = dirty_area->min_y; y < dirty_area->max_y; y++) { \
      int reps = sysdep_display_params.heightscale-1; \
      FUNC_NAME(BLIT_LINE)( \
        ((SRC_PIXEL *)(bitmap->line[y])) + dirty_area->min_x, \
        ((SRC_PIXEL *)(bitmap->line[y])) + dirty_area->max_x, \
        line_dest, palette->lookup); \
      while (--reps) { \
        memcpy(line_dest+DEST_WIDTH, line_dest, \
          (vis_in_dest_out->max_x-vis_in_dest_out->min_x)*DEST_PIXEL_SIZE); \
        line_dest += DEST_WIDTH; \
      } \
      line_dest += 2*DEST_WIDTH; \
    } \
  } \
}
