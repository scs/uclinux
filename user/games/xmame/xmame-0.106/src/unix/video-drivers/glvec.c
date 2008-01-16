/*****************************************************************

  OpenGL vector routines

  Copyright 1998 by Mike Oliphant - oliphant@ling.ed.ac.uk
  Copyright 2004 Hans de Goede - j.w.r.degoede@hhs.nl
   
    http://www.ling.ed.ac.uk/~oliphant/glmame

  Improved by Sven Goethel, http://www.jausoft.com, sgoethel@jausoft.com

  This code may be used and distributed under the terms of the
  Mame license

ChangeLog:

16 August 2004 (Hans de Goede):
-fixed vector support (vecshift now always = 16)
-modified to use: vector_register_aux_renderer,
 now we no longer need any core modifcations, and
 the code is somewhat cleaner.

Todo:
-add clipping support, needs someone with better openGL skills
 then me.

*****************************************************************/

#include <math.h>
#include "glmame.h"
#include "sysdep/sysdep_display_priv.h"

/* from mame's vidhrdw/vector.h */
#define VCLEAN  0
#define VDIRTY  1
#define VCLIP   2

enum { NONE, LINE, POINT };

static GLdouble xmin, ymin, xmax, ymax = 0.0;

/*
 * Adds a line end point to the vertices list. The vector processor emulation
 * needs to call this.
 */
INLINE void glvec_add_point (GLdouble x, GLdouble y)
{
  if(!cabview) {
    disp__glVertex2d(x,y);
  } else {
    GLdouble z;
    if (sysdep_display_params.orientation & SYSDEP_DISPLAY_SWAPXY)
      CalcCabPointbyViewpoint(x*sysdep_display_params.height,
        y*sysdep_display_params.width, &x, &y, &z);
    else
      CalcCabPointbyViewpoint(x*sysdep_display_params.width,
        y*sysdep_display_params.height, &x, &y, &z);
    disp__glVertex3d(x,y,z);
  }
}

INLINE int glvec_clip_line_get_flags(GLdouble *x, GLdouble *y)
{
  int flags=0; 

  if (*x < xmin)
    flags |= 0x01;

  if (*x > xmax)
    flags |= 0x02;

  if (*y < ymin)
    flags |= 0x04;

  if (*y > ymax)
    flags |= 0x08;

  return flags;
}

/* Cohen-Sutherland line-clipping algorithm,
   based on the article: http://www.nondot.org/~sabre/graphpro/line6.html */
INLINE int glvec_clip_line(GLdouble *x1, GLdouble *y1, GLdouble *x2,
  GLdouble *y2)
{
  int flags1 = glvec_clip_line_get_flags(x1, y1);
  int flags2 = glvec_clip_line_get_flags(x2, y2);
  
  while(flags1 || flags2)
  {
    int flags;
    GLdouble t,x,y;

    /* line completly outside viewport? */
    if (flags1 & flags2)
      return 0;
  
    /* deterine which endpoint to clip */
    if (flags1)
      flags = flags1;
    else
      flags = flags2;
    
    /* do the actual clipping */    
    if (flags&0x01)          /* x < xmin */
    {
      t = (xmin-*x1)/(*x2-*x1);
      x = xmin;
      y = *y1 + t*(*y2-*y1);
    }
    else if (flags&0x02)     /* x > xmax */
    {
      t = (xmax-*x1)/(*x2-*x1);
      x = xmax;
      y = *y1 + t*(*y2-*y1);
    }
    else if (flags&0x04)     /* y < ymin */
    {
      t = (ymin-*y1)/(*y2-*y1);
      y = ymin;
      x = *x1 + t*(*x2-*x1);
    }
    else /* (flags&0x08) */  /* y > ymax */
    {
      t = (ymax-*y1)/(*y2-*y1);
      y = ymax;
      x = *x1 + t*(*x2-*x1);
    }

    /* update x,y and flags */
    if (flags1)
    {
      *x1 = x;
      *y1 = y;
      flags1 = glvec_clip_line_get_flags(x1, y1);
    }
    else
    {
      *x2 = x;
      *y2 = y;
      flags2 = glvec_clip_line_get_flags(x2, y2);
    }
  }
  return 1;
}

int glvec_renderer(point *pt, int num_points)
{
  if (num_points)
  {
    GLdouble x1,x2,y1,y2,oldx=0.0,oldy=0.0;
    int state = NONE;
    
    disp__glNewList(veclist,GL_COMPILE);
    CHECK_GL_ERROR ();
    
    xmin = 0.0;
    ymin = 0.0;
    xmax = 1.0;
    ymax = 1.0;

    while(num_points)
    {
      if (pt->status == VCLIP)
      {
        xmin = vecx + pt->x/vecscalex;
        ymin = vecy + pt->y/vecscaley;
        xmax = vecx + pt->arg1/vecscalex;
        ymax = vecy + pt->arg2/vecscaley;
      }
      else
      {
        x1 = oldx;
        y1 = oldy;
        x2 = vecx + pt->x/vecscalex;
        y2 = vecy + pt->y/vecscaley;
        oldx = x2;
        oldy = y2;
        
        if (pt->intensity && glvec_clip_line(&x1, &y1, &x2, &y2))
        {
          int red, green, blue;
          rgb_t color;
          
          if (pt->callback)
            color = pt->callback();
          else
            color = pt->col;
        
          red   = (color & 0xff0000) >> 16;
          green = (color & 0x00ff00) >> 8;
          blue  = (color & 0x0000ff);

          disp__glColor4ub(red, green, blue, pt->intensity);
          
          if((fabs(x1-x2) < 0.001) && (fabs(y1-y2) < 0.001))
          {
            /* Hack to draw points -- very short lines don't show up
             *
             * But games, e.g. tacscan have zero lines within the LINE_STRIP,
             * so we do try to continue the line strip :-) */
            switch(state)
            {
              case LINE:
                GL_END();
              case NONE:
                GL_BEGIN(GL_POINTS);
                state = POINT;
                break;
              case POINT:
                break;
            }
          }
          else
          {
            switch(state)
            {
              case POINT:
                GL_END();
              case NONE:
                GL_BEGIN(GL_LINE_STRIP);
                state = LINE;
                glvec_add_point(x1, y1);
                break;
              case LINE:
                break;
            }
          }
          glvec_add_point(x2, y2);
        }
        /* end the linestrip if the intensity is 0 or we've clipped the last
           coordinate */
        if((state == LINE) && ((pt->intensity==0) || (x2!=oldx) || (y2!=oldy)))
        {
          GL_END();
          state = NONE;
        }
      }
      pt++;
      num_points--;
    }

    if (state != NONE)
      GL_END();

    disp__glEndList();
    CHECK_GL_ERROR ();
  }
  return 0;
}
