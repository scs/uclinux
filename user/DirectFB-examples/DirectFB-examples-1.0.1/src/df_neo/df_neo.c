/* DirectFB Scaling and compositing demo
 *
 * Copyright (C) 2001, 2002  convergence integrated media GmbH
 * Copyright (C) 2002        convergence GmbH
 * Authors: Sven Neumann <sven@convergence.de>
 *          Denis Oliver Kropp <dok@convergence.de>
 *
 * Ported from:
 * GdkPixbuf library - Scaling and compositing demo
 * Copyright (C) 1999 The Free Software Foundation
 *
 * Authors: Federico Mena-Quintero <federico@gimp.org>
 */

#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>

#include <directfb.h>


#ifndef MIN
#define MIN(x,y) ((x) > (y) ? (y) : (x))
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#endif

#ifndef FALSE
#define FALSE (0)
#define TRUE (!FALSE)
#endif

/* macro for a safe call to DirectFB functions */
#define DFBCHECK(x...)                                                     \
               err = x;                                                    \
               if (err != DFB_OK) {                                        \
                    fprintf( stderr, "%s <%d>:\n\t", __FILE__, __LINE__ ); \
                    DirectFBErrorFatal (#x, err);                         \
               }

static const char *image_names[] =
{
  DATADIR"/apple-red.png",
  DATADIR"/gnome-applets.png",
  DATADIR"/gnome-calendar.png",
  DATADIR"/gnome-foot.png",
  DATADIR"/gnome-gmush.png",
  DATADIR"/gnome-gimp.png",
  DATADIR"/gnome-gsame.png",
  DATADIR"/gnu-keys.png"
};

#define N_IMAGES (int)((sizeof (image_names) / sizeof (image_names[0])))

#define BACKGROUND_NAME  DATADIR"/background.jpg"

#define CYCLE_LEN        60
#define FRAME_DELAY       0   /*  50  */


static IDirectFBSurface *background;
static int               back_width;
static int               back_height;

static IDirectFBSurface *images[N_IMAGES];
static int               image_widths[N_IMAGES];
static int               image_heights[N_IMAGES];

static IDirectFB        *dfb;
static IDirectFBSurface *primary;
static IDirectFBSurface *sub;

static DFBResult         err;

static int               frame_num;
static int               colorize = TRUE;
static int               alpha    = TRUE;
static int               on_crack = FALSE;


static void
load_images (void)
{
  DFBSurfaceDescription   dsc;
  IDirectFBImageProvider *provider;
  int i;

  for (i = 0; i < N_IMAGES; i++)
    {
      DFBCHECK(dfb->CreateImageProvider (dfb, image_names[i], &provider));
      DFBCHECK(provider->GetSurfaceDescription (provider, &dsc));

      image_widths[i]  = dsc.width;
      image_heights[i] = dsc.height;

      DFBCHECK(dfb->CreateSurface (dfb, &dsc, &images[i]));

      provider->RenderTo (provider, images[i], NULL);

      provider->Release (provider);
    }
}

static void
release_images (void)
{
  int i;

  for (i = 0; i < N_IMAGES; i++)
    images[i]->Release (images[i]);
}

static void
timeout (unsigned int cycle_len)
{
  float f;
  float xmid, ymid;
  float radius;
  int   i;
  DFBSurfaceBlittingFlags blit_flags;

  if (!on_crack)
    {
      sub->SetBlittingFlags (sub, DSBLIT_NOFX);
      sub->Blit (sub, background, NULL, 0, 0);
    }

  f = (float) (frame_num % cycle_len) / cycle_len;

  xmid = back_width / 2.0f;
  ymid = back_height / 2.0f;

  radius = MIN (xmid, ymid) / 2.0f;

  blit_flags = DSBLIT_BLEND_ALPHACHANNEL;
  if (alpha)
    blit_flags |= DSBLIT_BLEND_COLORALPHA;
  if (colorize)
    blit_flags |= DSBLIT_COLORIZE;

  sub->SetBlittingFlags (sub, blit_flags);

  for (i = 0; i < N_IMAGES; i++)
    {
      DFBRectangle dest;
      float ang;
      float r;
      float k;
      int   xpos, ypos;
      int   iw, ih;

      ang = 2.0f * (float) M_PI * (float) i / N_IMAGES - f * 2.0f * (float) M_PI;

      iw = image_widths[i];
      ih = image_heights[i];

      r = radius + (radius / 3.0f) * sinf (f * 2.0 * M_PI);

      xpos = xmid + r * cosf (ang) - iw / 2.0f;
      ypos = ymid + r * sinf (ang) - ih / 2.0f;

      k = (i & 1) ? sinf (f * 2.0f * (float) M_PI) : cosf (f * 2.0f * (float) M_PI);
      k = 2.0f * k * k;
      k = MAX (0.25f, k);

      dest.x = xpos;
      dest.y = ypos;
      dest.w = iw * k;
      dest.h = ih * k;

      sub->SetColor (sub, xpos, ypos, 255-xpos,
                     ((i & 1)
                      ? fabs (255 * sinf (f * 2.0f * (float) M_PI))
                      : fabs (255 * cosf (f * 2.0f * (float) M_PI))));

      sub->StretchBlit (sub, images[i], NULL, &dest);
    }

  if (!on_crack)
    primary->Flip (primary, NULL, DSFLIP_ONSYNC);

  frame_num++;
}

int
main (int    argc,
      char **argv)
{
  DFBSurfaceDescription   dsc;
  DFBSurfaceDescription   back_dsc;
  DFBRectangle            rect;
  IDirectFBImageProvider *provider;
  IDirectFBEventBuffer   *keybuffer;
  DFBInputEvent           evt;
  int                     width;
  int                     height;
  int                     quit;
  unsigned int            cycle_len;
  struct timeval          tv;
  long                    start_time;
  long                    current_time;
  long                    frame_delay;
  long                    delay;

  frame_delay = delay = FRAME_DELAY;
  cycle_len   = CYCLE_LEN;
  quit        = FALSE;

  DFBCHECK (DirectFBInit (&argc, &argv));

  if (argc > 1 && argv[1] && strcmp (argv[1], "--on-crack") == 0)
    on_crack = TRUE;

  /* create the super interface */
  DFBCHECK (DirectFBCreate (&dfb));

  dfb->SetCooperativeLevel (dfb, DFSCL_FULLSCREEN);
  DFBCHECK (dfb->CreateInputEventBuffer (dfb, DICAPS_KEYS,
                                         DFB_FALSE, &keybuffer));

  /*  create the primary surface  */
  dsc.flags = DSDESC_CAPS;
  dsc.caps  = DSCAPS_PRIMARY;

  if (!on_crack) {
       dsc.caps |= DSCAPS_TRIPLE;

       if (dfb->CreateSurface (dfb, &dsc, &primary) != DFB_OK) {
            dsc.caps = (dsc.caps & ~DSCAPS_TRIPLE) | DSCAPS_DOUBLE;
            DFBCHECK (dfb->CreateSurface (dfb, &dsc, &primary));
       }
  }
  else
       DFBCHECK (dfb->CreateSurface (dfb, &dsc, &primary));

  /* load size of background image */
  DFBCHECK (dfb->CreateImageProvider (dfb, BACKGROUND_NAME, &provider));
  DFBCHECK (provider->GetSurfaceDescription (provider, &back_dsc));
  back_width  = back_dsc.width;
  back_height = back_dsc.height;

  if (!back_width || !back_height)
    return -1;

  /*  create the background surface  */
  DFBCHECK (dfb->CreateSurface (dfb, &back_dsc, &background));
  provider->RenderTo (provider, background, NULL);
  provider->Release (provider);

  /*  create subsurface in the middle of the screen */
  primary->GetSize (primary, &width, &height);
  rect.x = (width  - back_width)  / 2;
  rect.y = (height - back_height) / 2;
  rect.w = back_width;
  rect.h = back_height;
  primary->GetSubSurface (primary, &rect, &sub);

  if (on_crack)
    {
      /* clear screen */
      primary->Clear (primary, 0, 0, 0, 0xff);
    }
  else
    {
      /*  fill screen and backbuffers with tiled background  */
      primary->TileBlit (primary, background, NULL, rect.x, rect.y);
      primary->Flip (primary, NULL, 0) ;
      primary->TileBlit (primary, background, NULL, rect.x, rect.y);
      primary->Flip (primary, NULL, 0) ;
      primary->TileBlit (primary, background, NULL, rect.x, rect.y);

      primary->SetClip (primary, NULL);
    }

  /*  load the remaining images  */
  load_images ();

  frame_num = 0;

  while (!quit)
    {
      gettimeofday (&tv, NULL);
      start_time = tv.tv_sec * 1000 + tv.tv_usec / 1000;

      timeout (cycle_len);

      while (keybuffer->GetEvent (keybuffer, DFB_EVENT(&evt)) == DFB_OK)
        {
          if (evt.type == DIET_KEYPRESS)
            {
              switch (evt.key_id)
                {
                case DIKI_LEFT:
                  frame_delay = MIN (500, frame_delay + 5);
                  break;
                case DIKI_RIGHT:
                  frame_delay = MAX (0, frame_delay - 5);
                  break;
                case DIKI_UP:
                  cycle_len = MIN (600, cycle_len + 6);
                  break;
                case DIKI_DOWN:
                  cycle_len = cycle_len > 6 ? cycle_len - 6 : 6;
                  break;
                case DIKI_SPACE:
                case DIKI_ENTER:
                  colorize = !colorize;
                  break;
                case DIKI_A:
                  alpha = !alpha;
                  break;
                case DIKI_HOME:
                  cycle_len   = CYCLE_LEN;
                  frame_delay = FRAME_DELAY;
                  colorize    = TRUE;
                  alpha       = TRUE;
                  break;
                case DIKI_ESCAPE:
                case DIKI_Q:
                  quit = TRUE;
                  break;
                default:
                  break;
                }

              switch (evt.key_symbol)
                {
                case DIKS_OK:
                  colorize = !colorize;
                  break;
                case DIKS_BACK:
                case DIKS_STOP:
                  quit = TRUE;
                  break;
                default:
                  break;
                }
            }
        }

      if (frame_delay)
        {
          gettimeofday (&tv, NULL);
          current_time = tv.tv_sec * 1000 + tv.tv_usec / 1000;

          delay = frame_delay - (current_time - start_time);
          if (delay > 0)
            usleep (1000 * delay);
        }
    }

  keybuffer->Release (keybuffer);
  release_images ();
  background->Release (background);
  sub->Release (sub);
  primary->Release (primary);
  dfb->Release (dfb);

  return 0;
}
