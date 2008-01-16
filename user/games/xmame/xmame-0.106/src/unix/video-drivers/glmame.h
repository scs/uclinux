/*****************************************************************

  GLmame include file

  Copyright 1998 by Mike Oliphant - oliphant@ling.ed.ac.uk

    http://www.ling.ed.ac.uk/~oliphant/glmame

  Improved by Sven Goethel, http://www.jausoft.com, sgoethel@jausoft.com

  This code may be used and distributed under the terms of the
  Mame license

*****************************************************************/

#ifndef _GLMAME_H
#define _GLMAME_H

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>
#include <assert.h>
#include <math.h>
#include "MAME32.h"
#include "wgl_tool.h"
#include "wgl_GDIDisplay.h"
#else
#include <ctype.h>
#include <math.h>
#include <dlfcn.h>
#define CALLBACK
#endif

#include "gltool.h"
#include "sysdep/sysdep_display.h"

/* Camera panning stuff */

typedef enum {pan_goto,pan_moveto,pan_repeat,pan_end,pan_nocab} PanType;

struct CameraPan {
  PanType type;      /* Type of pan */
  GLdouble lx,ly,lz;  /* Location of camera */
  GLdouble px,py,pz;  /* Vector to point camera along */
  GLdouble nx,ny,nz;  /* Normal to camera direction */
  int frames;        /* Number of frames for transition */
};

/* glcab.c */
extern GLubyte **cabimg;
extern GLuint *cabtex;
extern struct CameraPan *cpan;
extern int numpans;
extern GLuint cablist;

/* xgl.c */
extern int antialias;
extern int antialiasvec;
extern int bilinear;
extern int force_text_width_height;
extern float gl_beam;
extern int cabview;
extern char *cabname;

/* glgen.c */
extern GLuint veclist;
extern GLdouble  s__cscr_w_view, s__cscr_h_view;
extern GLdouble vx_cscr_p1, vy_cscr_p1, vz_cscr_p1, 
        vx_cscr_p2, vy_cscr_p2, vz_cscr_p2,
        vx_cscr_p3, vy_cscr_p3, vz_cscr_p3, 
	vx_cscr_p4, vy_cscr_p4, vz_cscr_p4;
extern GLdouble vecx, vecy, vecscalex, vecscaley;

/* glvec.c */
int glvec_renderer(point *start, int num_points);

/* glcab.c */
int LoadCabinet (const char *fname);

/* glgen.c */
int  gl_open_display(int reopen);
void gl_close_display(void);
const char *gl_update_display(mame_bitmap *bitmap,
	  rectangle *vis_area,  rectangle *dirty_area,
	  struct sysdep_palette_struct *palette, int flags);
void CalcCabPointbyViewpoint( 
  GLdouble vx_gscr_view, GLdouble vy_gscr_view, 
  GLdouble *vx_p, GLdouble *vy_p, GLdouble *vz_p);
int  gl_set_windowsize(void);
int  gl_set_cabview (int new_value);

/* glexport */
void gl_save_screen_snapshot();

/* gljpeg */
GLubyte *read_JPEG_file(char *);

#endif /* _GLMAME_H */
