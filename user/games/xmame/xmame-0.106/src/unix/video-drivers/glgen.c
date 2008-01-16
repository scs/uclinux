/***************************************************************** 

  Generic OpenGL routines

  Copyright 1998 by Mike Oliphant - oliphant@ling.ed.ac.uk

    http://www.ling.ed.ac.uk/~oliphant/glmame

  Improved by Sven Goethel, http://www.jausoft.com, sgoethel@jausoft.com

  This code may be used and distributed under the terms of the
  Mame license

*****************************************************************/

#include <math.h>
#include "glmame.h"
#include <GL/glext.h>
#include "sysdep/sysdep_display_priv.h"
#include "x11.h"

/* private functions */
static void gl_free_textures(void);
static GLdouble CompareVec (GLdouble i, GLdouble j, GLdouble k,
	    GLdouble x, GLdouble y, GLdouble z);
static void TranslatePointInPlane   (
	      GLdouble vx_p1, GLdouble vy_p1, GLdouble vz_p1,
	      GLdouble vx_nw, GLdouble vy_nw, GLdouble vz_nw,
	      GLdouble vx_nh, GLdouble vy_nh, GLdouble vz_nh,
	      GLdouble x_off, GLdouble y_off,
	      GLdouble *vx_p, GLdouble *vy_p, GLdouble *vz_p );
static void ScaleThisVec (GLdouble i, GLdouble j, GLdouble k,
	      GLdouble * x, GLdouble * y, GLdouble * z);
static void AddToThisVec (GLdouble i, GLdouble j, GLdouble k,
	      GLdouble * x, GLdouble * y, GLdouble * z);
static GLdouble LengthOfVec (GLdouble x, GLdouble y, GLdouble z);
static void NormThisVec (GLdouble * x, GLdouble * y, GLdouble * z);
static void DeltaVec (GLdouble x1, GLdouble y1, GLdouble z1,
	       GLdouble x2, GLdouble y2, GLdouble z2,
	       GLdouble * dx, GLdouble * dy, GLdouble * dz);
static void CrossVec (GLdouble a1, GLdouble a2, GLdouble a3,
	  GLdouble b1, GLdouble b2, GLdouble b3,
	  GLdouble * c1, GLdouble * c2, GLdouble * c3);
static void CopyVec(GLdouble *ax,GLdouble *ay,GLdouble *az,            /* dest   */
	     const GLdouble bx,const GLdouble by,const GLdouble bz     /* source */
                  );
static void CalcFlatTexPoint( int x, int y, GLdouble texwpervw, GLdouble texhpervh, 
		       GLdouble * px, GLdouble * py);
static int SetupFrustum (void);
static int SetupOrtho (void);

static void WAvg (GLdouble perc, GLdouble x1, GLdouble y1, GLdouble z1,
	   GLdouble x2, GLdouble y2, GLdouble z2,
	   GLdouble * ax, GLdouble * ay, GLdouble * az);

static GLenum  gl_bitmap_format;
static GLenum  gl_bitmap_type;
static GLsizei text_width;
static GLsizei text_height;
static int texnumx;
static int texnumy;
static int maxtexnumx;
static int maxtexnumy;
static int bitmap_dirty;

/* The squares that are tiled to make up the game screen polygon */
struct TexSquare
{
  GLubyte *texture;
  GLuint texobj;
  GLdouble x1, y1, z1, x2, y2, z2, x3, y3, z3, x4, y4, z4;
  GLdouble fx1, fy1, fx2, fy2, fx3, fy3, fx4, fy4;
  GLdouble xcov, ycov;
};

static struct TexSquare *texgrid = NULL;

/**
 * cscr..: cabinet screen points:
 * 
 * are defined within <model>.cab in the following order:
 *	1.) left  - top
 *	2.) right - top
 *	3.) right - bottom
 *	4.) left  - bottom
 *
 * are read in reversed:
 *	1.) left  - bottom
 *	2.) right - bottom
 *	3.) right - top
 *	4.) left  - top
 *
 * so we do have a positiv (Q I) coord system ;-), of course:
 *	left   < right
 *	bottom < top
 */
GLdouble vx_cscr_p1, vy_cscr_p1, vz_cscr_p1, 
        vx_cscr_p2, vy_cscr_p2, vz_cscr_p2,
        vx_cscr_p3, vy_cscr_p3, vz_cscr_p3, 
	vx_cscr_p4, vy_cscr_p4, vz_cscr_p4;

/**
 * cscr..: cabinet screen dimension vectors
 *	
 * 	these are the cabinet-screen's width/height in the cabinet's world-coord !!
 */
static GLdouble  vx_cscr_dw, vy_cscr_dw, vz_cscr_dw; /* the width (world-coord) , p1-p2 */
static GLdouble  vx_cscr_dh, vy_cscr_dh, vz_cscr_dh; /* the height (world-coord), p1-p4 */

static GLdouble  s__cscr_w,  s__cscr_h;              /* scalar width/height (world-coord) */
GLdouble  s__cscr_w_view, s__cscr_h_view;     /* scalar width/height (view-coord) */

/* screen x-axis (world-coord), normalized v__cscr_dw */
static GLdouble vx_scr_nx, vy_scr_nx, vz_scr_nx; 

/* screen y-axis (world-coord), normalized v__cscr_dh */
static GLdouble vx_scr_ny, vy_scr_ny, vz_scr_ny; 

/* screen z-axis (world-coord), the normalized cross product of v__cscr_dw,v__cscr_dh */
static GLdouble vx_scr_nz, vy_scr_nz, vz_scr_nz; 

/* x/y-factor for view/world coord translation */
static GLdouble cab_vpw_fx; /* s__cscr_w_view / s__cscr_w */
static GLdouble cab_vpw_fy; /* s__cscr_h_view / s__cscr_h */

/**
 * gscr..: game screen dimension vectors
 *	
 * 	these are the game portion of the cabinet-screen's width/height 
 *      in the cabinet's world-coord !!
 *
 *	gscr[wh]d[xyz] <= cscr[wh]d[xyz]
 */

static GLdouble vx_gscr_dw, vy_gscr_dw, vz_gscr_dw; /* the width (world-coord) */
static GLdouble vx_gscr_dh, vy_gscr_dh, vz_gscr_dh; /* the height (world-coord) */

static GLdouble  s__gscr_w, s__gscr_h;              /* scalar width/height (world-coord) */
static GLdouble  s__gscr_w_view, s__gscr_h_view;    /* scalar width/height (view-coord) */

static GLdouble  s__gscr_offx, s__gscr_offy;          /* delta game start (world-coord) */

static GLdouble  s__gscr_offx_view, s__gscr_offy_view;/* delta game-start (view-coord) */

/**
*
* ALL GAME SCREEN VECTORS ARE IN FINAL ORIENTATION (e.g. if (sysdep_display_params.orientation & SYSDEP_DISPLAY_SWAPXY))
*
* v__gscr_p1 = v__cscr_p1   + 
*              s__gscr_offx * v__scr_nx + s__gscr_offy * v__scr_ny ;
*
* v__gscr_p2  = v__gscr_p1  + 
*              s__gscr_w    * v__scr_nx + 0.0          * v__scr_ny ;
*
* v__gscr_p3  = v__gscr_p2  + 
*              0.0          * v__scr_nx + s__gscr_h    * v__scr_ny ;
*
* v__gscr_p4  = v__gscr_p3  - 
*              s__gscr_w    * v__scr_nx - 0.0          * v__scr_ny ;
*
* v__gscr_p4b = v__gscr_p1  + 
*              0.0          * v__scr_nx + s__gscr_h    * v__scr_ny ;
*
* v__gscr_p4a == v__gscr_p4b
*/
static GLdouble vx_gscr_p1, vy_gscr_p1, vz_gscr_p1; 
static GLdouble vx_gscr_p2, vy_gscr_p2, vz_gscr_p2; 
static GLdouble vx_gscr_p3, vy_gscr_p3, vz_gscr_p3; 
static GLdouble vx_gscr_p4, vy_gscr_p4, vz_gscr_p4; 

static GLdouble mxModel[16];
static GLdouble mxProjection[16];

/* Camera panning variables */
static int currentpan = 0;
static int lastpan    = 0;
static int panframe   = 0;

/* Misc variables */
static int gl_texture_init;
static int cab_loaded;
static unsigned short *colorBlittedMemory = NULL;
static unsigned char *empty_text = NULL;
static int unpack_alignment;

/* Vector variables */
GLuint veclist=0;
GLdouble vecx, vecy, vecscalex, vecscaley;

#ifndef NOGLCHECKS
#define RETURN_IF_GL_ERROR() \
  { \
    GLenum err = disp__glGetError(); \
    if((err != GL_NO_ERROR)) \
    { \
      PRINT_GL_ERROR("GLERROR", err); \
      return 1; \
    } \
  }
#else
#define RETURN_IF_GL_ERROR()
#endif

/* ---------------------------------------------------------------------- */
/* ------------ New OpenGL Specials ------------------------------------- */
/* ---------------------------------------------------------------------- */
static int gl_set_bilinear (int new_value)
{
  int x, y;
  bilinear = new_value;
  if (bilinear)
  {
    if (cabtex)
    {
	    disp__glBindTexture (GL_TEXTURE_2D, cabtex[0]);
	    RETURN_IF_GL_ERROR ();
	    disp__glTexParameteri (GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
	    RETURN_IF_GL_ERROR ();
	    disp__glTexParameteri (GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
	    RETURN_IF_GL_ERROR ();
    }

    for (y = 0; y < maxtexnumy; y++)
    {
      for (x = 0; x < maxtexnumx; x++)
      {
        disp__glBindTexture (GL_TEXTURE_2D, texgrid[y * texnumx + x].texobj);
	RETURN_IF_GL_ERROR ();
        disp__glTexParameteri (GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        RETURN_IF_GL_ERROR ();
        disp__glTexParameteri (GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        RETURN_IF_GL_ERROR ();
      }
    }
  }
  else
  {
    if (cabtex)
    {
	    disp__glBindTexture (GL_TEXTURE_2D, cabtex[0]);
	    RETURN_IF_GL_ERROR ();
	    disp__glTexParameteri (GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
	    RETURN_IF_GL_ERROR ();
	    disp__glTexParameteri (GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
	    RETURN_IF_GL_ERROR ();
    }

    for (y = 0; y < maxtexnumy; y++)
    {
      for (x = 0; x < maxtexnumx; x++)
      {
        disp__glBindTexture (GL_TEXTURE_2D, texgrid[y * texnumx + x].texobj);
        RETURN_IF_GL_ERROR ();
        disp__glTexParameteri (GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
        RETURN_IF_GL_ERROR ();
        disp__glTexParameteri (GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
        RETURN_IF_GL_ERROR ();
      }
    }
  }
  return 0;
}

int gl_set_cabview (int new_value)
{
  if (!cab_loaded)
    return 0;

  cabview = new_value;
  if (cabview)
  {
        currentpan = 1;
	lastpan    = 0;
	panframe   = 0;
	return SetupFrustum ();
  } else {
	return SetupOrtho ();
  }
}

static int gl_set_antialias(int new_value)
{
  antialias = new_value;
  if (antialias)
  {
    disp__glShadeModel (GL_SMOOTH);
    RETURN_IF_GL_ERROR ();
    disp__glEnable (GL_POLYGON_SMOOTH);
    RETURN_IF_GL_ERROR ();
    disp__glEnable (GL_LINE_SMOOTH);
    RETURN_IF_GL_ERROR ();
    disp__glEnable (GL_POINT_SMOOTH);
    RETURN_IF_GL_ERROR ();
  }
  else
  {
    disp__glShadeModel (GL_FLAT);
    RETURN_IF_GL_ERROR ();
    disp__glDisable (GL_POLYGON_SMOOTH);
    RETURN_IF_GL_ERROR ();
    disp__glDisable (GL_LINE_SMOOTH);
    RETURN_IF_GL_ERROR ();
    disp__glDisable (GL_POINT_SMOOTH);
    RETURN_IF_GL_ERROR ();
  }
  return 0;
}

static int gl_set_beam(float new_value)
{
  gl_beam = new_value;
  disp__glLineWidth(gl_beam);
  RETURN_IF_GL_ERROR ();
  disp__glPointSize(gl_beam);
  RETURN_IF_GL_ERROR ();
  return 0;
}

int gl_open_display (int reopen)
{
  const unsigned char * glVersion;
  int x, y;
  struct TexSquare *tsq;
  GLint format=0;
  int format_ok=0;
  int bytes_per_pixel = (sysdep_display_params.depth + 7) / 8;
  static int firsttime = 1;

  if (firsttime)
  {
    glVersion = disp__glGetString(GL_VERSION);
    RETURN_IF_GL_ERROR ();

    fprintf(stderr, "\nGLINFO: OpenGL Driver Information:\n");
    fprintf(stderr, "\tvendor: %s,\n\trenderer %s,\n\tversion %s\n", 
          disp__glGetString(GL_VENDOR), 
          disp__glGetString(GL_RENDERER),
          glVersion);

    if(!(glVersion[0]>'1' ||
         (glVersion[0]=='1' && glVersion[2]>='2') ) )
    {
         fprintf(stderr, "error: an OpenGL >= 1.2 capable driver is required!\n");
         return 1;
    }

    fprintf(stderr, "GLINFO: GLU Driver Information:\n");
    fprintf(stderr, "\tversion %s\n",
          disp__gluGetString(GLU_VERSION));

    firsttime = 0;
  }

  disp__glClearColor (0, 0, 0, 1);
  RETURN_IF_GL_ERROR ();
  disp__glClear (GL_COLOR_BUFFER_BIT);
  RETURN_IF_GL_ERROR ();
  disp__glFlush ();
  RETURN_IF_GL_ERROR ();
  disp__glDepthFunc (GL_LEQUAL);
  RETURN_IF_GL_ERROR ();
  disp__glBlendFunc (GL_SRC_ALPHA, GL_ONE);
  RETURN_IF_GL_ERROR ();

  if(!reopen)
  {
    if (gl_set_antialias (antialias))
      return 1;
    if (gl_set_beam(gl_beam))
      return 1;

    if ((cab_loaded = LoadCabinet (cabname)))
    {
      /* Calulate delta vectors for screen height and width */
      DeltaVec (vx_cscr_p1, vy_cscr_p1, vz_cscr_p1, vx_cscr_p2, vy_cscr_p2, vz_cscr_p2,
                &vx_cscr_dw, &vy_cscr_dw, &vz_cscr_dw);
      DeltaVec (vx_cscr_p1, vy_cscr_p1, vz_cscr_p1, vx_cscr_p4, vy_cscr_p4, vz_cscr_p4,
                &vx_cscr_dh, &vy_cscr_dh, &vz_cscr_dh);

      s__cscr_w = LengthOfVec (vx_cscr_dw, vy_cscr_dw, vz_cscr_dw);
      s__cscr_h = LengthOfVec (vx_cscr_dh, vy_cscr_dh, vz_cscr_dh);


              /*	  
              ScaleThisVec ( -1.0,  1.0,  1.0, &vx_cscr_dh, &vy_cscr_dh, &vz_cscr_dh);
              ScaleThisVec ( -1.0,  1.0,  1.0, &vx_cscr_dw, &vy_cscr_dw, &vz_cscr_dw);
              */

      CopyVec( &vx_scr_nx, &vy_scr_nx, &vz_scr_nx,
                vx_cscr_dw,  vy_cscr_dw,  vz_cscr_dw);
      NormThisVec (&vx_scr_nx, &vy_scr_nx, &vz_scr_nx);

      CopyVec( &vx_scr_ny, &vy_scr_ny, &vz_scr_ny,
                vx_cscr_dh,  vy_cscr_dh,  vz_cscr_dh);
      NormThisVec (&vx_scr_ny, &vy_scr_ny, &vz_scr_ny);

      CrossVec (vx_cscr_dw, vy_cscr_dw, vz_cscr_dw,
                vx_cscr_dh, vy_cscr_dh, vz_cscr_dh,
                &vx_scr_nz, &vy_scr_nz, &vz_scr_nz);
      NormThisVec (&vx_scr_nz, &vy_scr_nz, &vz_scr_nz);

      #ifdef GLDEBUG
      {
        GLdouble t1, t1x, t1y, t1z;
        
        /**
         * assertions ...
         */
        CopyVec( &t1x, &t1y, &t1z,
                 vx_scr_nx, vy_scr_nx, vz_scr_nx);
        ScaleThisVec (s__cscr_w,s__cscr_w,s__cscr_w,
                      &t1x, &t1y, &t1z);
        t1 =  CompareVec (t1x, t1y, t1z, vx_cscr_dw,  vy_cscr_dw,  vz_cscr_dw);

        fprintf(stderr, "GLINFO: test v__cscr_dw - ( v__scr_nx * s__cscr_w ) = %f\n", t1);
        fprintf(stderr, "\t v__cscr_dw = %f / %f / %f\n", vx_cscr_dw,  vy_cscr_dw,  vz_cscr_dw);
        fprintf(stderr, "\t v__scr_nx = %f / %f / %f\n", vx_scr_nx, vy_scr_nx, vz_scr_nx);
        fprintf(stderr, "\t s__cscr_w  = %f \n", s__cscr_w);

        CopyVec( &t1x, &t1y, &t1z,
                 vx_scr_ny, vy_scr_ny, vz_scr_ny);
        ScaleThisVec (s__cscr_h,s__cscr_h,s__cscr_h,
                      &t1x, &t1y, &t1z);
        t1 =  CompareVec (t1x, t1y, t1z, vx_cscr_dh,  vy_cscr_dh,  vz_cscr_dh);

        fprintf(stderr, "GLINFO: test v__cscr_dh - ( v__scr_ny * s__cscr_h ) = %f\n", t1);
        fprintf(stderr, "\t v__cscr_dh = %f / %f / %f\n", vx_cscr_dh,  vy_cscr_dh,  vz_cscr_dh);
        fprintf(stderr, "\t v__scr_ny  = %f / %f / %f\n", vx_scr_ny, vy_scr_ny, vz_scr_ny);
        fprintf(stderr, "\t s__cscr_h   = %f \n", s__cscr_h);
      }
      #endif
    }
    else if (cabview)
    {
      fprintf(stderr, "GLERROR: Unable to load cabinet %s\n", cabname);
      cabview = 0;
    }
  }
  else if(colorBlittedMemory)
  {
    free(colorBlittedMemory);
    colorBlittedMemory = NULL;
  }

  /* draw vectors? */
  if (sysdep_display_params.vec_src_bounds && !veclist)
  {
    veclist=disp__glGenLists(1);
    RETURN_IF_GL_ERROR ();
  }

  /* fill the sysdep_display_properties struct & determine bitmap format */
  sysdep_display_properties.max_width  = -1;
  sysdep_display_properties.max_height = -1;
  memset(&sysdep_display_properties.palette_info, 0, sizeof(struct
    sysdep_palette_info));
  switch(sysdep_display_params.depth)
  {
    case 15:
      /* ARGB1555 */
      sysdep_display_properties.palette_info.red_mask   = 0x00007C00;
      sysdep_display_properties.palette_info.green_mask = 0x000003E0;
      sysdep_display_properties.palette_info.blue_mask  = 0x0000001F;
      sysdep_display_properties.palette_info.depth      = 15;
      sysdep_display_properties.palette_info.bpp        = 16;
      gl_bitmap_format = GL_BGRA;       /* A R G B */
      gl_bitmap_type   = GL_UNSIGNED_SHORT_1_5_5_5_REV;
      break;
    case 16:
      /* RGB565 */
      sysdep_display_properties.palette_info.red_mask   = 0x0000F800;
      sysdep_display_properties.palette_info.green_mask = 0x000007E0;
      sysdep_display_properties.palette_info.blue_mask  = 0x0000001F;
      sysdep_display_properties.palette_info.depth      = 16;
      sysdep_display_properties.palette_info.bpp        = 16;
      gl_bitmap_format = GL_RGB;        /* R G B */
      gl_bitmap_type   = GL_UNSIGNED_SHORT_5_6_5;
      break;
    case 32:
      /* ARGB8888 */
      sysdep_display_properties.palette_info.red_mask   = 0x00FF0000;
      sysdep_display_properties.palette_info.green_mask = 0x0000FF00;
      sysdep_display_properties.palette_info.blue_mask  = 0x000000FF;
      sysdep_display_properties.palette_info.depth      = 24;
      sysdep_display_properties.palette_info.bpp        = 32;
      gl_bitmap_format = GL_BGRA;     /* A R G B */
      gl_bitmap_type   = GL_UNSIGNED_INT_8_8_8_8_REV;
      break;
  }
  sysdep_display_properties.vector_renderer = glvec_renderer;

  if (sysdep_display_params.orientation & SYSDEP_DISPLAY_SWAPXY)
  {
    x = sysdep_display_params.height;
    y = sysdep_display_params.width;
  }
  else
  {
    x = sysdep_display_params.width;
    y = sysdep_display_params.height;
  }
    
  if(!reopen || ((maxtexnumx*text_width) < x) || ((maxtexnumy*text_height) < y))
  {
    if (reopen)
      gl_free_textures();

    if (sysdep_display_params.orientation & SYSDEP_DISPLAY_SWAPXY)
    {
      x = sysdep_display_params.max_height;
      y = sysdep_display_params.max_width;
    }
    else
    {
      x = sysdep_display_params.max_width;
      y = sysdep_display_params.max_height;
    }

    /* determine the texture size to use */
    if(force_text_width_height>0)
    {
      text_height = text_width = force_text_width_height;
      fprintf (stderr, "GLINFO: force_text_width_height := %d x %d\n",
               text_height, text_width);
    }
    else
    {
      /* round text_width and height up to a power of 2 */
      for(text_width =1;text_width <x;text_width *=2) {}
      for(text_height=1;text_height<y;text_height*=2) {}
    }

    /* Test the max texture size */
    while(!format_ok && text_width>=64 && text_height>=64)
    {
      disp__glTexImage2D (GL_PROXY_TEXTURE_2D, 0,
                    GL_RGB,
                    text_width, text_height,
                    0, gl_bitmap_format, gl_bitmap_type, 0);
      RETURN_IF_GL_ERROR ();

      disp__glGetTexLevelParameteriv
        (GL_PROXY_TEXTURE_2D, 0, GL_TEXTURE_INTERNAL_FORMAT, &format);
      RETURN_IF_GL_ERROR ();
      
      switch(sysdep_display_params.depth)
      {
        case 15:
        case 16:
          if(format == GL_RGB || format == GL_RGB5)
            format_ok = 1;
          break;
        case 32:
          if(format == GL_RGB || format == GL_RGB8)
            format_ok = 1;
          break;
      }

      if (!format_ok)
      {
        fprintf (stderr,
          "GLINFO: Needed texture [%dx%d] too big (format=0x%X), ",
          text_height, text_width, format);
        if (text_width > text_height)
          text_width /= 2;
        else
          text_height /= 2;
        fprintf (stderr, "trying [%dx%d] !\n", text_height, text_width);
      }
    }

    if(!format_ok)
    {
      fprintf (stderr, "GLERROR: Give up .. usable texture size not available, or texture config error !\n");
      return 1;
    }

    /* calculate the number of textures we need */  
    maxtexnumx = (x + text_width  - 1) / text_width;
    maxtexnumy = (y + text_height - 1) / text_height;
    fprintf (stderr, "GLINFO: texture-usage %d*width=%d, %d*height=%d\n",
                   (int) maxtexnumx, (int) text_width, (int) maxtexnumy,
                   (int) text_height);

    /* allocate some buffers */
    texgrid    = calloc(maxtexnumx * maxtexnumy, sizeof (struct TexSquare));
    empty_text = calloc(text_width*text_height, bytes_per_pixel);
    if (!texgrid || !empty_text)
    {
      fprintf(stderr, "GLERROR: couldn't allocate memory\n");
      return 1;
    }

    /* create the textures */
    for (y = 0; y < maxtexnumy; y++)
    {
      for (x = 0; x < maxtexnumx; x++)
      {
        tsq = texgrid + y * maxtexnumx + x;
    
        tsq->texobj=0;
        disp__glGenTextures (1, &(tsq->texobj));
        RETURN_IF_GL_ERROR ();
        disp__glBindTexture (GL_TEXTURE_2D, tsq->texobj);
        RETURN_IF_GL_ERROR ();

        if(disp__glIsTexture(tsq->texobj) == GL_FALSE)
        {
          fprintf (stderr, "GLERROR ain't a texture (glGenText): texnum x=%d, y=%d, texture=%d\n",
                  x, y, tsq->texobj);
        }
        RETURN_IF_GL_ERROR ();

        disp__glTexImage2D (GL_TEXTURE_2D, 0,
                      GL_RGB,
                      text_width, text_height,
                      0, gl_bitmap_format, gl_bitmap_type, empty_text);
        RETURN_IF_GL_ERROR ();
        disp__glTexParameterf(GL_TEXTURE_2D, GL_TEXTURE_PRIORITY, 1.0);
        RETURN_IF_GL_ERROR ();
        disp__glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP);
        RETURN_IF_GL_ERROR ();
        disp__glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP);
        RETURN_IF_GL_ERROR ();
        disp__glTexEnvf(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
        RETURN_IF_GL_ERROR ();
      }	/* for all texnumx */
    }  /* for all texnumy */
    free (empty_text);
    empty_text   = NULL;

    if (gl_set_bilinear (bilinear))
      return 1;
  }
  
  /* do we need a buffer to write the bitmap to after palette lookup? */
  if(sysdep_display_params.depth == 16)
  {
    colorBlittedMemory = malloc(sysdep_display_params.max_width *
      sysdep_display_params.max_height * bytes_per_pixel);
    if (!colorBlittedMemory)
    {
      fprintf(stderr, "GLERROR: couldn't allocate memory\n");
      return 1;
    }
    fprintf(stderr, "GLINFO: Using bit blit to map color indices !!\n");
  } else {
    fprintf(stderr, "GLINFO: Using true color mode (no color indices, but direct color)!!\n");
  }

  /* done */
  fprintf(stderr, "GLINFO: depth=%d, rgb 0x%X, 0x%X, 0x%X (true color mode)\n",
		sysdep_display_params.depth, 
		sysdep_display_properties.palette_info.red_mask, sysdep_display_properties.palette_info.green_mask, 
		sysdep_display_properties.palette_info.blue_mask);
  gl_texture_init = 0;
  bitmap_dirty    = 2;

  disp__glGetIntegerv(GL_UNPACK_ALIGNMENT, &unpack_alignment);
  
  return gl_set_windowsize();
}

static void gl_free_textures(void)
{
  /* FIXME free opengl texture ids */
  if (empty_text)
  {
    free (empty_text);
    empty_text = NULL;
  }
  if (texgrid)
  {
    free(texgrid);
    texgrid = NULL;
  }
}

/* Close down the virtual screen */
void gl_close_display (void)
{
  CHECK_GL_BEGINEND();
  CHECK_GL_ERROR();
  
  /* FIXME unload cabinet */

  if(colorBlittedMemory!=NULL)
  {
    free(colorBlittedMemory);
    colorBlittedMemory = NULL;
  }
  if (veclist)
  {
    disp__glDeleteLists(veclist, 1);
    CHECK_GL_ERROR();
    veclist = 0;
  }
  gl_free_textures();
}

/**
 * the given bitmap MUST be the original mame core bitmap !!!
 *    - no swapxy, flipx or flipy and no resize !
 *    - shall be Machine->scrbitmap
 */
static void InitTextures (mame_bitmap *bitmap, rectangle *vis_area)
{
  int x=0, y=0;
  unsigned char *line_1=0;
  struct TexSquare *tsq=0;
  int line_len;
  int bytes_per_pixel = (sysdep_display_params.depth + 7) / 8;
  GLdouble texwpervw, texhpervh;
  /* the original (unoriented) width & height */
  int orig_width; 
  int orig_height;

  if (sysdep_display_params.orientation & SYSDEP_DISPLAY_SWAPXY)
  {
    orig_width  = sysdep_display_params.height; 
    orig_height = sysdep_display_params.width;
  }
  else
  {
    orig_width  = sysdep_display_params.width; 
    orig_height = sysdep_display_params.height;
  }

  texnumx = (orig_width +text_width -1) / text_width;
  texnumy = (orig_height+text_height-1) / text_height;

  /**
   * texwpervw, texhpervh:
   * 	how much the texture covers the visual,
   * 	for both components (width/height) (percent).
   */
  texwpervw = (GLdouble) text_width / (GLdouble)orig_width;
  if (texwpervw > 1.0)
    texwpervw = 1.0;

  texhpervh = (GLdouble) text_height / (GLdouble)orig_height;
  if (texhpervh > 1.0)
    texhpervh = 1.0;

  if(sysdep_display_params.depth == 16) 
  {
    line_1   = (unsigned char *)colorBlittedMemory;
    line_len = orig_width;
  }
  else
  {
    unsigned char *line_2;
    line_1   = (unsigned char *) bitmap->line[vis_area->min_y];
    line_2   = (unsigned char *) bitmap->line[vis_area->min_y + 1];
    line_len = (line_2 - line_1) / bytes_per_pixel;
    line_1  += vis_area->min_x * bytes_per_pixel;
  }

  disp__glPixelStorei (GL_UNPACK_ROW_LENGTH, line_len);
  CHECK_GL_ERROR ();

  if (cab_loaded)
  {
    /**
     *
     * Cabinet-Screen Ratio:
     */
     GLdouble vx_gscr_p4b, vy_gscr_p4b, vz_gscr_p4b, t1;
     double game_aspect = (double)sysdep_display_params.width / (double)sysdep_display_params.height; 
     double cabn_aspect = (double)s__cscr_w / (double)s__cscr_h;

     if( game_aspect <= cabn_aspect )
     {
          /**
           * cabinet_width  >  game_width
           * cabinet_height == game_height 
           *
           * cabinet_height(view-coord) := sysdep_display_params.height(view-coord) 
           */
          s__cscr_h_view  = (GLdouble) sysdep_display_params.height;
          s__cscr_w_view  = s__cscr_h_view * cabn_aspect;

          s__gscr_h_view  = s__cscr_h_view;
          s__gscr_w_view  = s__gscr_h_view * game_aspect; 

          s__gscr_offy_view = 0.0;
          s__gscr_offx_view = ( s__cscr_w_view - s__gscr_w_view ) / 2.0;

     } else {
          /**
           * cabinet_width  <  game_width
           * cabinet_width  == game_width 
           *
           * cabinet_width(view-coord) := sysdep_display_params.width(view-coord) 
           */
          s__cscr_w_view  = (GLdouble) sysdep_display_params.width;
          s__cscr_h_view  = s__cscr_w_view / cabn_aspect;

          s__gscr_w_view  = s__cscr_w_view;
          s__gscr_h_view  = s__gscr_w_view / game_aspect; 

          s__gscr_offx_view = 0.0;
          s__gscr_offy_view = ( s__cscr_h_view - s__gscr_h_view ) / 2.0;

     }
     cab_vpw_fx = (GLdouble)s__cscr_w_view / (GLdouble)s__cscr_w ;
     cab_vpw_fy = (GLdouble)s__cscr_h_view / (GLdouble)s__cscr_h ;

     s__gscr_w   = (GLdouble)s__gscr_w_view  / cab_vpw_fx ;
     s__gscr_h   = (GLdouble)s__gscr_h_view  / cab_vpw_fy ;
     s__gscr_offx = (GLdouble)s__gscr_offx_view / cab_vpw_fx ;
     s__gscr_offy = (GLdouble)s__gscr_offy_view / cab_vpw_fy ;


     /**
      * ALL GAME SCREEN VECTORS ARE IN FINAL ORIENTATION (e.g. if (sysdep_display_params.orientation & SYSDEP_DISPLAY_SWAPXY))
      *
      * v__gscr_p1 = v__cscr_p1   + 
      *              s__gscr_offx * v__scr_nx + s__gscr_offy * v__scr_ny ;
      *
      * v__gscr_p2  = v__gscr_p1  + 
      *              s__gscr_w    * v__scr_nx + 0.0          * v__scr_ny ;
      *
      * v__gscr_p3  = v__gscr_p2  + 
      *              0.0          * v__scr_nx + s__gscr_h    * v__scr_ny ;
      *
      * v__gscr_p4  = v__gscr_p3  - 
      *              s__gscr_w    * v__scr_nx - 0.0          * v__scr_ny ;
      *
      * v__gscr_p4b = v__gscr_p1  + 
      *              0.0          * v__scr_nx + s__gscr_h    * v__scr_ny ;
      *
      * v__gscr_p4  == v__gscr_p4b
      */
     TranslatePointInPlane ( vx_cscr_p1, vy_cscr_p1, vz_cscr_p1,
                             vx_scr_nx, vy_scr_nx, vz_scr_nx,
                             vx_scr_ny, vy_scr_ny, vz_scr_ny,
                             s__gscr_offx, s__gscr_offy,
                             &vx_gscr_p1, &vy_gscr_p1, &vz_gscr_p1);

     TranslatePointInPlane ( vx_gscr_p1, vy_gscr_p1, vz_gscr_p1,
                             vx_scr_nx, vy_scr_nx, vz_scr_nx,
                             vx_scr_ny, vy_scr_ny, vz_scr_ny,
                             s__gscr_w, 0.0,
                             &vx_gscr_p2, &vy_gscr_p2, &vz_gscr_p2);

     TranslatePointInPlane ( vx_gscr_p2, vy_gscr_p2, vz_gscr_p2,
                             vx_scr_nx, vy_scr_nx, vz_scr_nx,
                             vx_scr_ny, vy_scr_ny, vz_scr_ny,
                             0.0, s__gscr_h,
                             &vx_gscr_p3, &vy_gscr_p3, &vz_gscr_p3);

     TranslatePointInPlane ( vx_gscr_p3, vy_gscr_p3, vz_gscr_p3,
                             vx_scr_nx, vy_scr_nx, vz_scr_nx,
                             vx_scr_ny, vy_scr_ny, vz_scr_ny,
                             -s__gscr_w, 0.0,
                             &vx_gscr_p4, &vy_gscr_p4, &vz_gscr_p4);

     TranslatePointInPlane ( vx_gscr_p1, vy_gscr_p1, vz_gscr_p1,
                             vx_scr_nx, vy_scr_nx, vz_scr_nx,
                             vx_scr_ny, vy_scr_ny, vz_scr_ny,
                             0.0, s__gscr_h,
                             &vx_gscr_p4b, &vy_gscr_p4b, &vz_gscr_p4b);

     t1 =  CompareVec (vx_gscr_p4,  vy_gscr_p4,  vz_gscr_p4,
                       vx_gscr_p4b, vy_gscr_p4b, vz_gscr_p4b);

    DeltaVec (vx_gscr_p1, vy_gscr_p1, vz_gscr_p1, vx_gscr_p2, vy_gscr_p2, vz_gscr_p2,
              &vx_gscr_dw, &vy_gscr_dw, &vz_gscr_dw);
    DeltaVec (vx_gscr_p1, vy_gscr_p1, vz_gscr_p1, vx_gscr_p4, vy_gscr_p4, vz_gscr_p4,
              &vx_gscr_dh, &vy_gscr_dh, &vz_gscr_dh);

#ifdef GLDEBUG
    fprintf(stderr, "GLINFO: test v__cscr_dh - ( v__scr_ny * s__cscr_h ) = %f\n", t1);
    fprintf(stderr, "GLINFO: cabinet vectors\n");
    fprintf(stderr, "\t cab p1     : %f / %f / %f \n", vx_cscr_p1, vy_cscr_p1, vz_cscr_p1);
    fprintf(stderr, "\t cab p2     : %f / %f / %f \n", vx_cscr_p2, vy_cscr_p2, vz_cscr_p2);
    fprintf(stderr, "\t cab p3     : %f / %f / %f \n", vx_cscr_p3, vy_cscr_p3, vz_cscr_p3);
    fprintf(stderr, "\t cab p4     : %f / %f / %f \n", vx_cscr_p4, vy_cscr_p4, vz_cscr_p4);
    fprintf(stderr, "\n") ;
    fprintf(stderr, "\t cab width  : %f / %f / %f \n", vx_cscr_dw, vy_cscr_dw, vz_cscr_dw);
    fprintf(stderr, "\t cab height : %f / %f / %f \n", vx_cscr_dh, vy_cscr_dh, vz_cscr_dh);
    fprintf(stderr, "\n");
    fprintf(stderr, "\t x axis : %f / %f / %f \n", vx_scr_nx, vy_scr_nx, vz_scr_nx);
    fprintf(stderr, "\t y axis : %f / %f / %f \n", vx_scr_ny, vy_scr_ny, vz_scr_ny);
    fprintf(stderr, "\t z axis : %f / %f / %f \n", vx_scr_nz, vy_scr_nz, vz_scr_nz);
    fprintf(stderr, "\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "\t cab wxh scal wd: %f x %f \n", s__cscr_w, s__cscr_h);
    fprintf(stderr, "\t cab wxh scal vw: %f x %f \n", s__cscr_w_view, s__cscr_h_view);
    fprintf(stderr, "\n");
    fprintf(stderr, "\t gam p1     : %f / %f / %f \n", vx_gscr_p1, vy_gscr_p1, vz_gscr_p1);
    fprintf(stderr, "\t gam p2     : %f / %f / %f \n", vx_gscr_p2, vy_gscr_p2, vz_gscr_p2);
    fprintf(stderr, "\t gam p3     : %f / %f / %f \n", vx_gscr_p3, vy_gscr_p3, vz_gscr_p3);
    fprintf(stderr, "\t gam p4     : %f / %f / %f \n", vx_gscr_p4, vy_gscr_p4, vz_gscr_p4);
    fprintf(stderr, "\t gam p4b    : %f / %f / %f \n", vx_gscr_p4b, vy_gscr_p4b, vz_gscr_p4b);
    fprintf(stderr, "\t gam p4-p4b : %f\n", t1);
    fprintf(stderr, "\n");
    fprintf(stderr, "\t gam width  : %f / %f / %f \n", vx_gscr_dw, vy_gscr_dw, vz_gscr_dw);
    fprintf(stderr, "\t gam height : %f / %f / %f \n", vx_gscr_dh, vy_gscr_dh, vz_gscr_dh);
    fprintf(stderr, "\n");
    fprintf(stderr, "\t gam wxh scal wd: %f x %f \n", s__gscr_w, s__gscr_h);
    fprintf(stderr, "\t gam wxh scal vw: %f x %f \n", s__gscr_w_view, s__gscr_h_view);
    fprintf(stderr, "\n");
    fprintf(stderr, "\t gam off  wd: %f / %f\n", s__gscr_offx, s__gscr_offy);
    fprintf(stderr, "\t gam off  vw: %f / %f\n", s__gscr_offx_view, s__gscr_offy_view);
    fprintf(stderr, "\n");
#endif
  }

  for (y = 0; y < texnumy; y++)
  {
    for (x = 0; x < texnumx; x++)
    {
      tsq = texgrid + y * texnumx + x;

      /* calculate the coordinates */
      if (x == texnumx - 1 && orig_width % text_width)
	tsq->xcov =
	  (GLdouble) (orig_width % text_width) / (GLdouble) text_width;
      else
	tsq->xcov = 1.0;

      if (y == texnumy - 1 && orig_height % text_height)
	tsq->ycov =
	  (GLdouble) (orig_height % text_height) / (GLdouble) text_height;
      else
	tsq->ycov = 1.0;

      CalcFlatTexPoint (x, y, texwpervw, texhpervh, &(tsq->fx1), &(tsq->fy1));
      CalcFlatTexPoint (x + 1, y, texwpervw, texhpervh, &(tsq->fx2), &(tsq->fy2));
      CalcFlatTexPoint (x + 1, y + 1, texwpervw, texhpervh, &(tsq->fx3), &(tsq->fy3));
      CalcFlatTexPoint (x, y + 1, texwpervw, texhpervh, &(tsq->fx4), &(tsq->fy4));

      CalcCabPointbyViewpoint( x*(GLdouble)text_width,
      		    y*(GLdouble)text_height,
                   &(tsq->x1), &(tsq->y1), &(tsq->z1));

      CalcCabPointbyViewpoint( x*(GLdouble)text_width  + tsq->xcov*(GLdouble)text_width,
      		    y*(GLdouble)text_height,
                   &(tsq->x2), &(tsq->y2), &(tsq->z2));

      CalcCabPointbyViewpoint( x*(GLdouble)text_width  + tsq->xcov*(GLdouble)text_width,
      		    y*(GLdouble)text_height + tsq->ycov*(GLdouble)text_height,
                   &(tsq->x3), &(tsq->y3), &(tsq->z3));

      CalcCabPointbyViewpoint( x*(GLdouble)text_width,
      		    y*(GLdouble)text_height + tsq->ycov*(GLdouble)text_height,
                   &(tsq->x4), &(tsq->y4), &(tsq->z4));

      /* calculate the pixel store data, to use the machine-bitmap for our texture */
      tsq->texture = line_1 +
        ( (y * text_height * line_len) + (x * text_width)) * bytes_per_pixel;
    }	/* for texnumx */
  }  /* for texnumy */

  if (sysdep_display_params.vec_src_bounds)
  {
    if(sysdep_display_params.vec_dest_bounds)
    {
      vecx = (GLdouble)sysdep_display_params.vec_dest_bounds->min_x/
        orig_width;
      vecy = (GLdouble)sysdep_display_params.vec_dest_bounds->min_y/
        orig_height;
      vecscalex = (65536.0 * orig_width *
        (sysdep_display_params.vec_src_bounds->max_x-
         sysdep_display_params.vec_src_bounds->min_x)) /
        ((sysdep_display_params.vec_dest_bounds->max_x + 1) -
         sysdep_display_params.vec_dest_bounds->min_x);
      vecscaley = (65536.0 * orig_height *
        (sysdep_display_params.vec_src_bounds->max_y-
         sysdep_display_params.vec_src_bounds->min_y)) /
        ((sysdep_display_params.vec_dest_bounds->max_y + 1) -
         sysdep_display_params.vec_dest_bounds->min_y);
    }
    else
    {
      vecx = 0.0;
      vecy = 0.0;
      vecscalex = (sysdep_display_params.vec_src_bounds->max_x-
        sysdep_display_params.vec_src_bounds->min_x) * 65536.0;
      vecscaley = (sysdep_display_params.vec_src_bounds->max_y-
        sysdep_display_params.vec_src_bounds->min_y) * 65536.0;
    }
  }
  gl_texture_init = 1;
}

/**
 * returns the length of the |(x,y,z)-(i,j,k)|
 */
static GLdouble
CompareVec (GLdouble i, GLdouble j, GLdouble k,
	    GLdouble x, GLdouble y, GLdouble z)
{
  GLdouble dx = x-i;
  GLdouble dy = y-j;
  GLdouble dz = z-k;

  return LengthOfVec(dx, dy, dz);
}

static void
AddToThisVec (GLdouble i, GLdouble j, GLdouble k,
	      GLdouble * x, GLdouble * y, GLdouble * z)
{
  *x += i ;
  *y += j ;
  *z += k ;
}

/**
 * TranslatePointInPlane:
 *
 * v__p = v__p1 + 
 *        x_off * v__nw +
 *        y_off * v__nh;
 */
static void TranslatePointInPlane   (
	      GLdouble vx_p1, GLdouble vy_p1, GLdouble vz_p1,
	      GLdouble vx_nw, GLdouble vy_nw, GLdouble vz_nw,
	      GLdouble vx_nh, GLdouble vy_nh, GLdouble vz_nh,
	      GLdouble x_off, GLdouble y_off,
	      GLdouble *vx_p, GLdouble *vy_p, GLdouble *vz_p )
{
   GLdouble tx, ty, tz;

   CopyVec( vx_p, vy_p, vz_p,
            vx_p1, vy_p1, vz_p1); 

   CopyVec( &tx, &ty, &tz,
	    vx_nw, vy_nw, vz_nw);

   ScaleThisVec (x_off, x_off, x_off,
                 &tx, &ty, &tz);

   AddToThisVec (tx, ty, tz,
                 vx_p, vy_p, vz_p);

   CopyVec( &tx, &ty, &tz,
	    vx_nh, vy_nh, vz_nh);

   ScaleThisVec (y_off, y_off, y_off,
                 &tx, &ty, &tz);

   AddToThisVec (tx, ty, tz,
                 vx_p, vy_p, vz_p);
}

static void
ScaleThisVec (GLdouble i, GLdouble j, GLdouble k,
	      GLdouble * x, GLdouble * y, GLdouble * z)
{
  *x *= i ;
  *y *= j ;
  *z *= k ;
}

static GLdouble
LengthOfVec (GLdouble x, GLdouble y, GLdouble z)
{
  return sqrt(x*x+y*y+z*z);
}

static void
NormThisVec (GLdouble * x, GLdouble * y, GLdouble * z)
{
  double len = LengthOfVec (*x, *y, *z);

  *x /= len ;
  *y /= len ;
  *z /= len ;
}

/* Compute a delta vector between two points */
static void
DeltaVec (GLdouble x1, GLdouble y1, GLdouble z1,
	  GLdouble x2, GLdouble y2, GLdouble z2,
	  GLdouble * dx, GLdouble * dy, GLdouble * dz)
{
  *dx = x2 - x1;
  *dy = y2 - y1;
  *dz = z2 - z1;
}

/* Compute a crossproduct vector of two vectors ( plane ) */
static void
CrossVec (GLdouble a1, GLdouble a2, GLdouble a3,
	  GLdouble b1, GLdouble b2, GLdouble b3,
	  GLdouble * c1, GLdouble * c2, GLdouble * c3)
{
  *c1 = a2*b3 - a3*b2; 
  *c2 = a3*b1 - a1*b3;
  *c3 = a1*b2 - a1*b1;
}

static void CopyVec(GLdouble *ax,GLdouble *ay,GLdouble *az,  /* dest   */
  const GLdouble bx,const GLdouble by,const GLdouble bz)     /* source */
{
	*ax=bx;
	*ay=by;
	*az=bz;
}

/**
 * Calculate texture points (world) for flat screen 
 *
 * x,y: 
 * 	texture index (scalar)
 *	
 * texwpervw, texhpervh:
 * 	how much the texture covers the visual,
 * 	for both components (width/height) (percent).
 *
 * px,py,pz:
 * 	the resulting cabinet point
 *
 */
static void CalcFlatTexPoint( int x, int y, GLdouble texwpervw,
  GLdouble texhpervh, GLdouble *px,GLdouble *py)
{
  *px=(double)x*texwpervw;
  if(*px>1.0) *px=1.0;
  *py=(double)y*texhpervh;
  if(*py>1.0) *py=1.0;
}

/**
 * vx_gscr_view,vy_gscr_view:
 * 	view-corrd within game-screen
 *
 * vx_p,vy_p,vz_p: 
 * 	world-coord within cab-screen
 */
void CalcCabPointbyViewpoint( 
		   GLdouble vx_gscr_view, GLdouble vy_gscr_view, 
                   GLdouble *vx_p, GLdouble *vy_p, GLdouble *vz_p
		 )
{
  GLdouble vx_gscr = (GLdouble)vx_gscr_view/cab_vpw_fx;
  GLdouble vy_gscr = (GLdouble)vy_gscr_view/cab_vpw_fy;

   /**
    * v__p  = v__gscr_p1  + vx_gscr * v__scr_nx + vy_gscr * v__scr_ny ;
    */

   TranslatePointInPlane ( vx_gscr_p1, vy_gscr_p1, vz_gscr_p1,
                           vx_scr_nx, vy_scr_nx, vz_scr_nx,
			   vx_scr_ny, vy_scr_ny, vz_scr_ny,
			   vx_gscr, vy_gscr,
			   vx_p, vy_p, vz_p);
}

/* Set up a frustum projection */
static int SetupFrustum (void)
{
  double vscrnaspect = (double) window_width / (double) window_height;

  disp__glMatrixMode (GL_PROJECTION);
  RETURN_IF_GL_ERROR ();
  disp__glLoadIdentity ();
  RETURN_IF_GL_ERROR ();
  disp__glFrustum (-vscrnaspect, vscrnaspect, -1.0, 1.0, 5.0, 100.0);
  RETURN_IF_GL_ERROR ();
  disp__glGetDoublev(GL_PROJECTION_MATRIX, mxProjection);
  RETURN_IF_GL_ERROR ();
  disp__glMatrixMode (GL_MODELVIEW);
  RETURN_IF_GL_ERROR ();
  disp__glLoadIdentity ();
  RETURN_IF_GL_ERROR ();
  disp__glTranslatef (0.0, 0.0, -20.0);
  RETURN_IF_GL_ERROR ();
  disp__glGetDoublev(GL_MODELVIEW_MATRIX, mxModel);
  RETURN_IF_GL_ERROR ();
  
  return 0;
}

/* Set up an orthographic projection */
static int SetupOrtho (void)
{
  disp__glMatrixMode (GL_PROJECTION);
  RETURN_IF_GL_ERROR ();
  disp__glLoadIdentity ();
  RETURN_IF_GL_ERROR ();
  disp__glOrtho (-0.5,  0.5, -0.5,  0.5,  1.0,  -1.0); /* normal display ! */
  RETURN_IF_GL_ERROR ();
  disp__glMatrixMode (GL_MODELVIEW);
  RETURN_IF_GL_ERROR ();
  disp__glLoadIdentity ();
  RETURN_IF_GL_ERROR ();
  disp__glRotated ( 180.0 , 1.0, 0.0, 0.0);
  RETURN_IF_GL_ERROR ();

  if ( (sysdep_display_params.orientation & SYSDEP_DISPLAY_FLIPX) )
  {
	disp__glRotated (  180.0 , 0.0, 1.0, 0.0);
        RETURN_IF_GL_ERROR ();
  }

  if ( (sysdep_display_params.orientation & SYSDEP_DISPLAY_FLIPY) )
  {
	disp__glRotated ( -180.0 , 1.0, 0.0, 0.0);
        RETURN_IF_GL_ERROR ();
  }

  if( (sysdep_display_params.orientation & SYSDEP_DISPLAY_SWAPXY) ) {
	disp__glRotated ( 180.0 , 0.0, 1.0, 0.0);
        RETURN_IF_GL_ERROR ();
  	disp__glRotated (  90.0 , 0.0, 0.0, 1.0 );
        RETURN_IF_GL_ERROR ();
  }

  disp__glTranslated ( -0.5 , -0.5, 0.0 );
  RETURN_IF_GL_ERROR ();

  return 0;  	
}

int gl_set_windowsize(void)
{
  CHECK_GL_BEGINEND();

  if (cabview)
  {
          disp__glViewport (0, 0, window_width, window_height);
          RETURN_IF_GL_ERROR ();
          return SetupFrustum ();
  }
  else
  {
          unsigned int vw, vh;
          int vscrndx;
          int vscrndy;

          mode_clip_aspect(window_width, window_height, &vw, &vh);
          
          vscrndx = (window_width  - vw) / 2;
          vscrndy = (window_height - vh) / 2;

          disp__glViewport (vscrndx, vscrndy, vw, vh);
          RETURN_IF_GL_ERROR ();
          return SetupOrtho ();
  }
}

/* Compute an average between two sets of 3D coordinates */
static void
WAvg (GLdouble perc, GLdouble x1, GLdouble y1, GLdouble z1,
      GLdouble x2, GLdouble y2, GLdouble z2,
      GLdouble * ax, GLdouble * ay, GLdouble * az)
{
  *ax = (1.0 - perc) * x1 + perc * x2;
  *ay = (1.0 - perc) * y1 + perc * y2;
  *az = (1.0 - perc) * z1 + perc * z2;
}

#if 0 /* not used */
static void drawGameAxis ()
{
  GLdouble tx, ty, tz;

	disp__glPushMatrix ();

	disp__glLineWidth(1.5f);
	disp__glBegin(GL_LINES);

	/** x-axis **/
	disp__glColor3d (1.0,1.0,1.0);
	disp__glVertex3d(0,0,0);

	disp__glColor3d (1.0,0.0,0.0);
        CopyVec( &tx, &ty, &tz,
	         vx_scr_nx, vy_scr_nx, vz_scr_nx);
        ScaleThisVec ( 5.0, 5.0, 5.0, &tx, &ty, &tz);
	disp__glVertex3d( tx, ty, tz );


	/** y-axis **/
	disp__glColor3d (1.0,1.0,1.0);
	disp__glVertex3d(0,0,0);

	disp__glColor3d (0.0,1.0,0.0);
        CopyVec( &tx, &ty, &tz,
	         vx_scr_ny, vy_scr_ny, vz_scr_ny);
        ScaleThisVec ( 5.0, 5.0, 5.0, &tx, &ty, &tz);
	disp__glVertex3d( tx, ty, tz );


	/** z-axis **/
	disp__glColor3d (1.0,1.0,1.0);
	disp__glVertex3d(0,0,0);

	disp__glColor3d (0.0,0.0,1.0);
        CopyVec( &tx, &ty, &tz,
	         vx_scr_nz, vy_scr_nz, vz_scr_nz);
        ScaleThisVec ( 5.0, 5.0, 5.0, &tx, &ty, &tz);
	disp__glVertex3d( tx, ty, tz );

	disp__glEnd();

	disp__glPopMatrix ();
	disp__glColor3d (1.0,1.0,1.0);
        CHECK_GL_ERROR ();
}
#endif

static void cabinetTextureRotationTranslation ()
{
	/**
	 * Be aware, this matrix is written in reverse logical
	 * order of GL commands !
	 *
	 * This is the way OpenGL stacks does work !
	 *
	 * So if you interprete this code,
	 * you have to start from the bottom from this block !!
	 *
	 * !!!!!!!!!!!!!!!!!!!!!!
	 */

	/** END  READING ... TRANSLATION / ROTATION **/

	/* go back on screen */
	disp__glTranslated ( vx_gscr_p1, vy_gscr_p1, vz_gscr_p1); 
	CHECK_GL_ERROR ();

	/* x-border -> I. Q */
	disp__glTranslated ( vx_gscr_dw/2.0, vy_gscr_dw/2.0, vz_gscr_dw/2.0);
	CHECK_GL_ERROR ();

	/* y-border -> I. Q */
	disp__glTranslated ( vx_gscr_dh/2.0, vy_gscr_dh/2.0, vz_gscr_dh/2.0);
	CHECK_GL_ERROR ();

	/********* CENTERED AT ORIGIN END  ****************/

	if ( (sysdep_display_params.orientation & SYSDEP_DISPLAY_FLIPX) )
	{
		disp__glRotated ( -180.0 , vx_scr_ny, vy_scr_ny, vz_scr_ny);
		CHECK_GL_ERROR ();
	}

	if ( (sysdep_display_params.orientation & SYSDEP_DISPLAY_FLIPY) )
	{
		disp__glRotated ( -180.0 , vx_scr_nx, vy_scr_nx, vz_scr_nx);
		CHECK_GL_ERROR ();
	}

	/********* CENTERED AT ORIGIN BEGIN ****************/
	if( (sysdep_display_params.orientation & SYSDEP_DISPLAY_SWAPXY) )
	{
		disp__glRotated ( -180.0 , vx_scr_ny, vy_scr_ny, vz_scr_ny);
		CHECK_GL_ERROR ();

		/* x-center */
		disp__glTranslated ( vx_gscr_dw/2.0, vy_gscr_dw/2.0, vz_gscr_dw/2.0);
		CHECK_GL_ERROR ();

		/* y-center */
		disp__glTranslated ( vx_gscr_dh/2.0, vy_gscr_dh/2.0, vz_gscr_dh/2.0);
		CHECK_GL_ERROR ();

		/* swap -> III. Q */
		disp__glRotated ( -90.0 , vx_scr_nz, vy_scr_nz, vz_scr_nz);
		CHECK_GL_ERROR ();
	} else {
		/* x-center */
		disp__glTranslated ( -vx_gscr_dw/2.0, -vy_gscr_dw/2.0, -vz_gscr_dw/2.0);
		CHECK_GL_ERROR ();

		/* y-center */
		disp__glTranslated ( vx_gscr_dh/2.0, vy_gscr_dh/2.0, vz_gscr_dh/2.0);
		CHECK_GL_ERROR ();
	}

	/* re-flip -> IV. Q     (normal) */
	disp__glRotated ( 180.0 , vx_scr_nx, vy_scr_nx, vz_scr_nx);
	CHECK_GL_ERROR ();

	/* go to origin -> I. Q (flipx) */
	disp__glTranslated ( -vx_gscr_p1, -vy_gscr_p1, -vz_gscr_p1); 
	CHECK_GL_ERROR ();

	/** START READING ... TRANSLATION / ROTATION **/
}

/* FIXME: do partial updates */
static void drawTextureDisplay (mame_bitmap *bitmap,
	  rectangle *vis_area,  rectangle *dirty_area,
	  struct sysdep_palette_struct *palette,
	  unsigned int flags)
{
  struct TexSquare *square;
  int x = 0, y = 0;
  static const double z_pos = 0.9f;

  if(!sysdep_display_params.vec_src_bounds || (flags & SYSDEP_DISPLAY_UI_DIRTY))
    bitmap_dirty=2;

  if (bitmap_dirty && (sysdep_display_params.depth == 16))
  {
    	unsigned short *dest=colorBlittedMemory;
    	int y,x;
    	int width;
		int unpack_alignment_2byte = unpack_alignment / 2;
    	if (sysdep_display_params.orientation & SYSDEP_DISPLAY_SWAPXY)
      	   width = sysdep_display_params.height;
    	else
    	   width = sysdep_display_params.width;
		/* Round the width to the GL_UNPACK_ALIGNMENT value in even-numbered bytes. */
    	if (width % unpack_alignment_2byte)
    	   width += unpack_alignment_2byte - (width % unpack_alignment_2byte);
    	for (y = vis_area->min_y; y <= vis_area->max_y; y++)
    	{
    	   for (x = vis_area->min_x; x<=vis_area->max_x; x++, dest++)
    	   {
    	      *dest=palette->lookup[((unsigned short*)(bitmap->line[y]))[x]];
    	   }
    	   dest += width - (vis_area->max_x - vis_area->min_x + 1);
    	}
  }

  disp__glColor4d (1.0, 1.0, 1.0, 1.0);
  CHECK_GL_ERROR ();
  disp__glEnable (GL_TEXTURE_2D);
  CHECK_GL_ERROR ();

  for (y = 0; y < texnumy; y++)
  {
    for (x = 0; x < texnumx; x++)
    {
      int width, height;
      
      square = texgrid + y * texnumx + x;
      
      if(x<(texnumx-1))
	width=text_width;
      else
      {
        width = ((vis_area->max_x + 1) - vis_area->min_x) % text_width;
        if (width == 0)
          width=text_width;
      }

      if(y<(texnumy-1))
	height=text_height;
      else
      {
        height = ((vis_area->max_y + 1) - vis_area->min_y) % text_height;
        if (height == 0)
          height=text_height;
      }

      disp__glBindTexture (GL_TEXTURE_2D, square->texobj);
      CHECK_GL_ERROR ();

      /* This is the quickest way I know of to update the texture */
      if (bitmap_dirty)
      {
	disp__glTexSubImage2D (GL_TEXTURE_2D, 0, 0, 0,
		width, height,
		gl_bitmap_format, gl_bitmap_type, square->texture);
        CHECK_GL_ERROR ();
        bitmap_dirty--;
      }

      if (cabview)
      {
  	GL_BEGIN(GL_QUADS);
	disp__glTexCoord2d (0, 0);
	disp__glVertex3d (square->x1, square->y1, square->z1);
	disp__glTexCoord2d (square->xcov, 0);
	disp__glVertex3d (square->x2, square->y2, square->z2);
	disp__glTexCoord2d (square->xcov, square->ycov);
	disp__glVertex3d (square->x3, square->y3, square->z3);
	disp__glTexCoord2d (0, square->ycov);
	disp__glVertex3d (square->x4, square->y4, square->z4);
	GL_END();
      }
      else
      {
	GL_BEGIN(GL_QUADS);
	disp__glTexCoord2d (0, 0);
	disp__glVertex3d (square->fx1, square->fy1, z_pos);
	disp__glTexCoord2d (square->xcov, 0);
	disp__glVertex3d (square->fx2, square->fy2, z_pos);
	disp__glTexCoord2d (square->xcov, square->ycov);
	disp__glVertex3d (square->fx3, square->fy3, z_pos);
	disp__glTexCoord2d (0, square->ycov);
	disp__glVertex3d (square->fx4, square->fy4, z_pos);
	GL_END();
      }
    } /* for all texnumx */
  } /* for all texnumy */

  disp__glDisable (GL_TEXTURE_2D);
  CHECK_GL_ERROR ();
  
  /* Draw the vectors if in vector mode */
  if (sysdep_display_params.vec_src_bounds)
  {
    if (antialiasvec)
    {
      disp__glEnable (GL_LINE_SMOOTH);
      CHECK_GL_ERROR ();
      disp__glEnable (GL_POINT_SMOOTH);
      CHECK_GL_ERROR ();
    }
    else
    {
      disp__glDisable (GL_LINE_SMOOTH);
      CHECK_GL_ERROR ();
      disp__glDisable (GL_POINT_SMOOTH);
      CHECK_GL_ERROR ();
    }

    disp__glShadeModel (GL_FLAT);
    CHECK_GL_ERROR ();
    disp__glEnable (GL_BLEND);
    CHECK_GL_ERROR ();
    disp__glCallList (veclist);
    CHECK_GL_BEGINEND();
    disp__glDisable (GL_BLEND);
    CHECK_GL_ERROR ();

    /* restore normal antialias settings */
    gl_set_antialias (antialias);
  }
}

/* Draw a frame in Cabinet mode */
static void UpdateCabDisplay (mame_bitmap *bitmap,
	  rectangle *vis_area,  rectangle *dirty_area,
	  struct sysdep_palette_struct *palette,
	  unsigned int flags)
{
  GLdouble camx, camy, camz;
  GLdouble dirx, diry, dirz;
  GLdouble normx, normy, normz;
  GLdouble perc;
  struct CameraPan *pan, *lpan;

  disp__glClear (GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
  CHECK_GL_ERROR ();
  disp__glPushMatrix ();
  CHECK_GL_ERROR ();

  /* Do the camera panning */
  if (cpan)
  {
    pan = cpan + currentpan;

/*
    fprintf(stderr, "GLINFO (glcab): pan %d/%d panframe %d/%d\n", 
    	currentpan, numpans, panframe, pan->frames);
*/

    if (0 >= panframe || panframe >= pan->frames)
    {
      lastpan = currentpan;
      currentpan += 1;
      if(currentpan>=numpans) currentpan=1;
      panframe = 0;
/*
      fprintf(stderr, "GLINFO (glcab): finished pan %d/%d\n", currentpan, numpans);
*/
    }

    switch (pan->type)
    {
    case pan_goto:
      camx = pan->lx;
      camy = pan->ly;
      camz = pan->lz;
      dirx = pan->px;
      diry = pan->px;
      dirz = pan->pz;
      normx = pan->nx;
      normy = pan->ny;
      normz = pan->nz;
      break;
    case pan_moveto:
      lpan = cpan + lastpan;
      perc = (GLdouble) panframe / (GLdouble) pan->frames;
      WAvg (perc, lpan->lx, lpan->ly, lpan->lz,
	    pan->lx, pan->ly, pan->lz, &camx, &camy, &camz);
      WAvg (perc, lpan->px, lpan->py, lpan->pz,
	    pan->px, pan->py, pan->pz, &dirx, &diry, &dirz);
      WAvg (perc, lpan->nx, lpan->ny, lpan->nz,
	    pan->nx, pan->ny, pan->nz, &normx, &normy, &normz);
      break;
    default:
      break;
    }

    disp__gluLookAt (camx, camy, camz, dirx, diry, dirz, normx, normy, normz);

    panframe++;
  }
  else
    disp__gluLookAt (-5.0, 0.0, 5.0, 0.0, 0.0, -5.0, 0.0, 1.0, 0.0);

  CHECK_GL_ERROR ();

  disp__glEnable (GL_DEPTH_TEST);
  CHECK_GL_ERROR ();

  /* Draw the cabinet */
  disp__glCallList (cablist);
  CHECK_GL_BEGINEND();

  /* Draw the game screen */
  cabinetTextureRotationTranslation ();
  drawTextureDisplay (bitmap, vis_area, dirty_area, palette, flags);

  disp__glDisable (GL_DEPTH_TEST);
  CHECK_GL_ERROR ();
}

/**
 * the given bitmap MUST be the original mame core bitmap !!!
 *    - no swapxy, flipx or flipy and no resize !
 *    - shall be Machine->scrbitmap
 */
static void UpdateGLDisplay (mame_bitmap *bitmap,
	  rectangle *vis_area,  rectangle *dirty_area,
	  struct sysdep_palette_struct *palette,
	  unsigned int flags)
{
  if (!gl_texture_init)
    InitTextures (bitmap, vis_area);

  if (cabview)
  {
    UpdateCabDisplay (bitmap, vis_area, dirty_area, palette, flags);
  }
  else
  {
    disp__glClear (GL_COLOR_BUFFER_BIT);
    CHECK_GL_ERROR ();
    disp__glPushMatrix ();
    CHECK_GL_ERROR ();
    drawTextureDisplay (bitmap, vis_area, dirty_area, palette, flags);
  }

  disp__glPopMatrix ();
  CHECK_GL_ERROR ();
}

/**
 * the given bitmap MUST be the original mame core bitmap !!!
 *    - no swapxy, flipx or flipy and no resize !
 *    - shall be Machine->scrbitmap
 */
const char *gl_update_display(mame_bitmap *bitmap,
	  rectangle *vis_area,  rectangle *dirty_area,
	  struct sysdep_palette_struct *palette, int flags)
{
  static char msg_buf[32];
  const char *msg = NULL;
  
  UpdateGLDisplay (bitmap, vis_area, dirty_area, palette, flags);

  if (flags & SYSDEP_DISPLAY_HOTKEY_OPTION0)
  {
    gl_set_bilinear (1 - bilinear);
    if(bilinear)
      msg = "bilinear filtering on";
    else
      msg = "bilinear filtering off";
  }
  if (flags & SYSDEP_DISPLAY_HOTKEY_OPTION3)
  {
    if (sysdep_display_params.vec_src_bounds)
    {
      antialiasvec = 1 - antialiasvec;
      if(antialiasvec)
        msg = "vector antialiasing on";
      else
        msg = "vector antialiasing off";
    }
    else
    {
      gl_set_antialias (1-antialias);
      if(antialias)
        msg = "antialiasing on";
      else
        msg = "antialiasing off";
    }
  }
  if (flags & SYSDEP_DISPLAY_HOTKEY_OPTION2)
  {
    if (gl_beam < 16.0)
    {
      gl_set_beam(gl_beam+0.5);
      snprintf(msg_buf, 32, "vector beam size %.1f", (double)gl_beam);
      msg = msg_buf;
    }
  }
  if (flags & SYSDEP_DISPLAY_HOTKEY_OPTION4)
  {
    if (gl_beam > 1.0)
    {
      gl_set_beam(gl_beam-0.5);
      snprintf(msg_buf, 32, "vector beam size %.1f", (double)gl_beam);
      msg = msg_buf;
    }
  }
  return msg;
}

#if 0 /* disabled for now */
mame_bitmap *osd_override_snapshot(mame_bitmap *bitmap,
		rectangle *bounds)
{
	do_snapshot = 1;
	return NULL;
}
#endif
