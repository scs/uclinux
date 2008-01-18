/*
   (c) Copyright 2000-2002  convergence integrated media GmbH.
   (c) Copyright 2002       convergence GmbH.
   All rights reserved.

   Written by Denis Oliver Kropp <dok@directfb.org>,
              Andreas Hundt <andi@fischlustig.de> and
              Sven Neumann <neo@directfb.org>.

   This file is subject to the terms and conditions of the MIT License:

   Permission is hereby granted, free of charge, to any person
   obtaining a copy of this software and associated documentation
   files (the "Software"), to deal in the Software without restriction,
   including without limitation the rights to use, copy, modify, merge,
   publish, distribute, sublicense, and/or sell copies of the Software,
   and to permit persons to whom the Software is furnished to do so,
   subject to the following conditions:

   The above copyright notice and this permission notice shall be
   included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
   IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
   CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
   TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <directfb.h>
#include <directfb_strings.h>
#include <directfb_util.h>

#include <direct/util.h>

#include <sys/time.h>  /* for gettimeofday() */
#include <sys/times.h> /* for times()        */
#include <stdio.h>     /* for fprintf()      */
#include <stdlib.h>    /* for rand()         */
#include <unistd.h>    /* for sleep()        */
#include <string.h>    /* for strcmp()       */

#include "pngtest3.h"

/* the super interface */
static IDirectFB *dfb;

/* the primary surface */
static IDirectFBSurface *primary;
static IDirectFBSurface *dest;

/* our "Press any key..." screen */
static IDirectFBSurface *intro;

/* some test images for blitting */
static IDirectFBSurface *cardicon;
static IDirectFBSurface *logo;
static IDirectFBSurface *simple;
static IDirectFBSurface *simple_ycbcr;
static IDirectFBSurface *colorkeyed;
static IDirectFBSurface *image32;
static IDirectFBSurface *image32a;
static IDirectFBSurface *image_lut;

static IDirectFBFont    *bench_font;
static IDirectFBFont    *ui_font;

static int stringwidth;
static int bench_fontheight;
static int ui_fontheight;

/* Media super interface and the provider for our images/font */
static IDirectFBImageProvider *provider;

/* Input interfaces: event buffer */
static IDirectFBEventBuffer *key_events;

static int SW, SH;

static int with_intro   = 0;
static int selfrunning  = 0;
static int do_system    = 0;
static int do_offscreen = 0;
static int do_noaccel   = 0;
static int show_results = 1;
static int mono_fonts   = 0;
static int accel_only   = 0;
static int do_dump      = 0;
static int do_aa        = 0;
static int do_matrix    = 0;
static int do_smooth    = 0;

/* some defines for benchmark test size and duration */
static int SX = 256;
static int SY = 256;

static int DEMOTIME = 3000;  /* milliseconds */

static const char *fontfile  = FONT;
static const char *imagefile;


#define MAX(a,b) ((a) > (b) ? (a) : (b))


/* macro for a safe call to DirectFB functions */
#define DFBCHECK(x...)                                                     \
          do {                                                             \
               err = x;                                                    \
               if (err != DFB_OK) {                                        \
                    fprintf( stderr, "%s <%d>:\n\t", __FILE__, __LINE__ ); \
                    DirectFBErrorFatal( #x, err );                         \
               }                                                           \
          } while (0)


/* the benchmarks */

static unsigned long long  draw_string             ( long t );
static unsigned long long  draw_string_blend       ( long t );
static unsigned long long  fill_rect               ( long t );
static unsigned long long  fill_rect_blend         ( long t );
static unsigned long long  fill_rects              ( long t );
static unsigned long long  fill_rects_blend        ( long t );
static unsigned long long  fill_triangle           ( long t );
static unsigned long long  fill_triangle_blend     ( long t );
static unsigned long long  draw_rect               ( long t );
static unsigned long long  draw_rect_blend         ( long t );
static unsigned long long  draw_lines              ( long t );
static unsigned long long  draw_lines_blend        ( long t );
static unsigned long long  fill_spans              ( long t );
static unsigned long long  fill_spans_blend        ( long t );
static unsigned long long  blit                    ( long t );
static unsigned long long  blit180                 ( long t );
static unsigned long long  blit_colorkeyed         ( long t );
static unsigned long long  blit_dst_colorkeyed     ( long t );
static unsigned long long  blit_convert            ( long t );
static unsigned long long  blit_colorize           ( long t );
static unsigned long long  blit_blend              ( long t );
static unsigned long long  blit_blend_colorize     ( long t );
static unsigned long long  blit_lut                ( long t );
static unsigned long long  blit_lut_blend          ( long t );
static unsigned long long  stretch_blit            ( long t );
static unsigned long long  stretch_blit_colorkeyed ( long t );
static unsigned long long  stretch_blit_ycbcr      ( long t );
static unsigned long long  stretch_blit_indexed    ( long t );
static unsigned long long  load_dfiff              ( long t );
static unsigned long long  load_gif                ( long t );
static unsigned long long  load_jpeg               ( long t );
static unsigned long long  load_png                ( long t );
static unsigned long long  load_image              ( long t );


typedef struct {
     char        desc[128];
     char       *message;
     char       *status;
     char       *option;
     bool        default_on;
     int         requested;
     long        result;
     DFBBoolean  accelerated;
     char       *unit;
     unsigned long long (* func) ( long );
} Demo;

enum {
     DEMO_LOAD_IMAGE,
     DEMO_DRAWSTRING,
     DEMO_DRAWSTRING_BLEND
};

static Demo demos[] = {
  { "Load Image",
    "Loading image files!",
    "Loading image files", "load-image <file>", false,
    0, 0, 0, "MPixel/sec", load_image },
  { "Anti-aliased Text",
    "This is the DirectFB benchmarking tool, let's start with some text!",
    "Anti-aliased Text", "draw-string", true,
    0, 0, 0, "KChars/sec",  draw_string },
  { "Anti-aliased Text (blend)",
    "Alpha blending based on color alpha",
    "Alpha Blended Anti-aliased Text", "draw-string-blend", true,
    0, 0, 0, "KChars/sec",  draw_string_blend },
  { "Fill Rectangle",
    "Ok, we'll go on with some opaque filled rectangles!",
    "Rectangle Filling", "fill-rect", true,
    0, 0, 0, "MPixel/sec", fill_rect },
  { "Fill Rectangle (blend)",
    "What about alpha blended rectangles?",
    "Alpha Blended Rectangle Filling", "fill-rect-blend", true,
    0, 0, 0, "MPixel/sec", fill_rect_blend },
  { "Fill Rectangles [10]",
    "Ok, we'll go on with some opaque filled rectangles!",
    "Rectangle Filling", "fill-rects", true,
    0, 0, 0, "MPixel/sec", fill_rects },
  { "Fill Rectangles [10] (blend)",
    "What about alpha blended rectangles?",
    "Alpha Blended Rectangle Filling", "fill-rects-blend", true,
    0, 0, 0, "MPixel/sec", fill_rects_blend },
  { "Fill Triangles",
    "Ok, we'll go on with some opaque filled triangles!",
    "Triangle Filling", "fill-triangle", true,
    0, 0, 0, "MPixel/sec", fill_triangle },
  { "Fill Triangles (blend)",
    "What about alpha blended triangles?",
    "Alpha Blended Triangle Filling", "fill-triangle-blend", true,
    0, 0, 0, "MPixel/sec", fill_triangle_blend },
  { "Draw Rectangle",
    "Now pass over to non filled rectangles!",
    "Rectangle Outlines", "draw-rect", true,
    0, 0, 0, "KRects/sec", draw_rect },
  { "Draw Rectangle (blend)",
    "Again, we want it with alpha blending!",
    "Alpha Blended Rectangle Outlines", "draw-rect-blend", true,
    0, 0, 0, "KRects/sec", draw_rect_blend },
  { "Draw Lines [10]",
    "Can we have some opaque lines, please?",
    "Line Drawing", "draw-line", true,
    0, 0, 0, "KLines/sec", draw_lines },
  { "Draw Lines [10] (blend)",
    "So what? Where's the blending?",
    "Alpha Blended Line Drawing", "draw-line-blend", true,
    0, 0, 0, "KLines/sec", draw_lines_blend },
  { "Fill Spans",
    "Can we have some spans, please?",
    "Span Filling", "fill-span", true,
    0, 0, 0, "MPixel/sec", fill_spans },
  { "Fill Spans (blend)",
    "So what? Where's the blending?",
    "Alpha Blended Span Filling", "fill-span-blend", true,
    0, 0, 0, "MPixel/sec", fill_spans_blend },
  { "Blit",
    "Now lead to some blitting demos! The simplest one comes first...",
    "Simple BitBlt", "blit", true,
    0, 0, 0, "MPixel/sec", blit },
  { "Blit 180",
    "Rotation?...",
    "Rotated BitBlt", "blit180", true,
    0, 0, 0, "MPixel/sec", blit180 },
  { "Blit colorkeyed",
    "Color keying would be nice...",
    "BitBlt with Color Keying", "blit-colorkeyed", true,
    0, 0, 0, "MPixel/sec", blit_colorkeyed },
  { "Blit destination colorkeyed",
    "Destination color keying is also possible...",
    "BitBlt with Destination Color Keying", "blit-dst-colorkeyed", true,
    0, 0, 0, "MPixel/sec", blit_dst_colorkeyed },
  { "Blit with format conversion",
    "What if the source surface has another format?",
    "BitBlt with on-the-fly format conversion", "blit-convert", true,
    0, 0, 0, "MPixel/sec", blit_convert },
  { "Blit with colorizing",
    "How does colorizing look like?",
    "BitBlt with colorizing", "blit-colorize", true,
    0, 0, 0, "MPixel/sec", blit_colorize },
  { "Blit from 32bit (blend)",
    "Here we go with alpha again!",
    "BitBlt with Alpha Channel", "blit-blend", true,
    0, 0, 0, "MPixel/sec", blit_blend },
  { "Blit from 32bit (blend) with colorizing",
    "Here we go with colorized alpha!",
    "BitBlt with Alpha Channel & Colorizing", "blit-blend-colorize", true,
    0, 0, 0, "MPixel/sec", blit_blend_colorize },
  { "Blit from 8bit palette",
    "Or even a palette?",
    "BitBlt from palette", "blit-lut", false,
    0, 0, 0, "MPixel/sec", blit_lut },
  { "Blit from 8bit palette (blend)",
    "With alpha blending based on alpha entries",
    "BitBlt from palette (blend)", "blit-lut-blend", false,
    0, 0, 0, "MPixel/sec", blit_lut_blend },
  { "Stretch Blit",
    "Stretching!!!!!",
    "Stretch Blit", "stretch-blit", true,
    0, 0, 0, "MPixel/sec", stretch_blit },
  { "Stretch Blit colorkeyed",
    "Stretching with Color Keying!!!",
    "Stretch Blit with Color Keying", "stretch-blit-colorkeyed", true,
    0, 0, 0, "MPixel/sec", stretch_blit_colorkeyed },
  { "Stretch Blit YCbCr",
    "Stretching YCbCr Source!!!",
    "Stretch Blit with YCbCr source", "stretch-blit-ycbcr", false,
    0, 0, 0, "MPixel/sec", stretch_blit_ycbcr },
  { "Stretch Blit indexed",
    "Stretching from indexed!!!",
    "Stretch Blit from indexed", "stretch-blit-indexed", false,
    0, 0, 0, "MPixel/sec", stretch_blit_indexed },
  { "Load DFIFF",
    "Loading DFIFF files!",
    "Loading DFIFF files", "load-dfiff", false,
    0, 0, 0, "MPixel/sec", load_dfiff },
  { "Load GIF",
    "Loading GIF files!",
    "Loading GIF files", "load-gif", false,
    0, 0, 0, "MPixel/sec", load_gif },
  { "Load JPEG",
    "Loading JPEG files!",
    "Loading JPEG files", "load-jpeg", false,
    0, 0, 0, "MPixel/sec", load_jpeg },
  { "Load PNG",
    "Loading PNG files!",
    "Loading PNG files", "load-png", false,
    0, 0, 0, "MPixel/sec", load_png },
};
static int num_demos = sizeof( demos ) / sizeof (demos[0]);

static Demo *current_demo;

static unsigned int rand_pool = 0x12345678;
static unsigned int rand_add  = 0x87654321;

static inline unsigned int myrand()
{
     rand_pool ^= ((rand_pool << 7) | (rand_pool >> 25));
     rand_pool += rand_add;
     rand_add  += rand_pool;

     return rand_pool;
}

static inline long myclock()
{
     struct timeval tv;

     gettimeofday (&tv, NULL);

     return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

static void print_usage()
{
     int i;

     printf ("DirectFB Benchmarking Demo version " VERSION "\n\n");
     printf ("Usage: df_dok [options]\n\n");
     printf ("Options:\n\n");
     printf ("  --duration <milliseconds>    Duration of each benchmark.\n");
     printf ("  --size     <width>x<height>  Set benchmark size.\n");
     printf ("  --pixelformat <pixelformat>  Set benchmark pixelformat.\n");
     printf ("  --system                     Do benchmarks in system memory.\n");
     printf ("  --offscreen                  Do benchmarks in offscreen memory.\n");
     printf ("  --dump                       Dump output of each test to a file, df_dok_...\n");
     printf ("  --font <filename>            Use the specified font file.\n");
     printf ("  --noaccel                    Don't use hardware acceleration.\n");
     printf ("  --accelonly                  Only show accelerated benchmarks.\n");
     printf ("  --mono                       Load fonts without anti-aliasing.\n");
     printf ("  --smooth                     Enable smooth up/down scaling option (experimental)\n");
     printf ("  --aa                         Turn on anti-aliasing for all benchmarks (experimental)\n");
     printf ("  --matrix                     Set a 3x2 transformation on all benchmarks (experimental)\n");
     printf ("  --noresults                  Don't show results screen.\n");
     printf ("  --help                       Print usage information.\n");
     printf ("  --dfb-help                   Output DirectFB usage information.\n\n");
     printf ("The following options allow to specify which benchmarks to run.\n");
     printf ("If none of these are given, all benchmarks are run.\n\n");
     for (i = 0; i < num_demos; i++) {
          printf ("  --%-26s %s\n", demos[i].option, demos[i].desc);
     }
     printf ("\n");
}

static void shutdown()
{
     /* release our interfaces to shutdown DirectFB */
     bench_font->Release( bench_font );
     ui_font->Release( ui_font );
     if (with_intro)
          intro->Release( intro );
     logo->Release( logo );
     simple->Release( simple );
     simple_ycbcr->Release( simple_ycbcr );
     cardicon->Release( cardicon );
     colorkeyed->Release( colorkeyed );
     image32->Release( image32 );
     image32a->Release( image32a );
     image_lut->Release( image_lut );
     dest->Release( dest );
     primary->Release( primary );
     key_events->Release( key_events );
     dfb->Release( dfb );
}

static void showMessage( const char *msg )
{
     DFBInputEvent ev;
     int err;

     while (key_events->GetEvent( key_events, DFB_EVENT(&ev) ) == DFB_OK) {
          if (ev.type == DIET_KEYPRESS) {
               switch (ev.key_symbol) {
                    case DIKS_ESCAPE:
                    case DIKS_SMALL_Q:
                    case DIKS_CAPITAL_Q:
                    case DIKS_BACK:
                    case DIKS_STOP:
                         shutdown();
                         exit( 42 );
                         break;
                    default:
                         break;
               }
          }
     }

     if (with_intro) {
          primary->SetBlittingFlags( primary, DSBLIT_NOFX );
          DFBCHECK(primary->Blit( primary, intro, NULL, 0, 0 ));

          primary->SetDrawingFlags( primary, DSDRAW_NOFX );
          primary->SetColor( primary, 0xFF, 0xFF, 0xFF, 0xFF );
          DFBCHECK(primary->DrawString( primary,
                                        msg, -1, SW/2, SH/2, DSTF_CENTER ));

          if (selfrunning) {
               usleep(1500000);
          }
          else {
               key_events->Reset( key_events );
               key_events->WaitForEvent( key_events );
          }
     }

     primary->Clear( primary, 0, 0, 0, 0x80 );
}

static void showResult()
{
     IDirectFBSurface       *meter;
     IDirectFBImageProvider *provider;
     DFBSurfaceDescription   dsc;
     DFBRectangle            rect;
     int   i, y, w, h, max_string_width = 0;
     char  rate[32];
     double factor = (SW-60) / 500000.0;

     if (dfb->CreateImageProvider( dfb,
                                   DATADIR"/meter.png", &provider ))
         return;

     provider->GetSurfaceDescription( provider, &dsc );
     dsc.height = dsc.height * SH / 1024;
     dfb->CreateSurface( dfb, &dsc, &meter );
     provider->RenderTo( provider, meter, NULL );
     provider->Release ( provider );

     cardicon->GetSize( cardicon, &w, &h );

     primary->Clear( primary, 0, 0, 0, 0x80 );

     primary->SetDrawingFlags( primary, DSDRAW_NOFX );
     primary->SetColor( primary, 0xFF, 0xFF, 0xFF, 0xFF );
     primary->DrawString( primary, "Results", -1,
                          SW/2, 2, DSTF_TOPCENTER );

     rect.x = 40;
     rect.y = ui_fontheight * 2;
     rect.h = dsc.height;

     primary->SetColor( primary, 0x66, 0x66, 0x66, 0xFF );
     primary->SetBlittingFlags( primary, DSBLIT_NOFX );

     for (i = 0; i < num_demos; i++) {
          if (!demos[i].requested || !demos[i].result)
               continue;

          rect.w = (double) demos[i].result * factor;
          primary->StretchBlit( primary, meter, NULL, &rect );
          if (rect.w < SW-60)
               primary->DrawLine( primary,
                                  40 + rect.w, rect.y + dsc.height,
                                  SW-20, rect.y + dsc.height );

          rect.y += dsc.height/2 + ui_fontheight + 2;
     }

     meter->Release( meter );

     y = ui_fontheight * 2 + dsc.height/2;
     for (i = 0; i < num_demos; i++) {
          if (!demos[i].requested || !demos[i].result)
               continue;

          primary->SetColor( primary, 0xCC, 0xCC, 0xCC, 0xFF );
          primary->DrawString( primary, demos[i].desc, -1, 20, y, DSTF_BOTTOMLEFT );

          snprintf( rate, sizeof (rate), "%2ld.%.3ld %s",
                    demos[i].result / 1000, demos[i].result % 1000, demos[i].unit);

          ui_font->GetStringExtents( ui_font, rate, -1, NULL, &rect );
          if (max_string_width < rect.w)
               max_string_width = rect.w;

          primary->SetColor( primary, 0xAA, 0xAA, 0xAA, 0xFF );
          primary->DrawString( primary, rate, -1, SW-20, y, DSTF_BOTTOMRIGHT );

          y += dsc.height/2 + ui_fontheight + 2;
     }

     y = ui_fontheight * 2 + dsc.height/2;
     for (i = 0; i < num_demos; i++) {
          if (!demos[i].requested || !demos[i].result)
               continue;

          if (demos[i].accelerated)
               primary->SetBlittingFlags( primary, DSBLIT_SRC_COLORKEY );
          else {
               primary->SetBlittingFlags( primary, DSBLIT_COLORIZE | DSBLIT_SRC_COLORKEY );
               primary->SetColor( primary, 0x20, 0x40, 0x40, 0xff );
          }
          primary->Blit( primary, cardicon,
                         NULL, SW - max_string_width - w - 25, y - h );

          y += dsc.height/2 + ui_fontheight + 2;
     }
     
     primary->Flip( primary, NULL, DSFLIP_NONE );

     key_events->Reset( key_events );
     key_events->WaitForEvent( key_events );
}

static void showStatus( const char *msg )
{
     primary->SetColor( primary, 0x40, 0x80, 0xFF, 0xFF );
     primary->DrawString( primary,
                          "DirectFB Benchmarking Demo:", -1,
                          ui_fontheight*5/3, SH, DSTF_TOP );

     primary->SetColor( primary, 0xFF, 0x00, 0x00, 0xFF );
     primary->DrawString( primary, msg, -1, SW-2, SH, DSTF_TOPRIGHT );

     if (do_system) {
          primary->SetColor( primary, 0x80, 0x80, 0x80, 0xFF );
          primary->DrawString( primary,
                               "Performing benchmark in system memory...",
                               -1, SW/2, SH/2, DSTF_CENTER );
     }
     else if (do_offscreen) {
          primary->SetColor( primary, 0x80, 0x80, 0x80, 0xFF );
          primary->DrawString( primary,
                               "Performing benchmark in offscreen memory...",
                               -1, SW/2, SH/2, DSTF_CENTER );
     }
}

static bool showAccelerated( DFBAccelerationMask  func,
                             IDirectFBSurface    *source )
{
     DFBAccelerationMask mask;

     dest->GetAccelerationMask( dest, source, &mask );

     if (mask & func) {
          primary->SetBlittingFlags( primary, DSBLIT_SRC_COLORKEY );

          current_demo->accelerated = DFB_TRUE;
     }
     else {
          primary->SetBlittingFlags( primary, DSBLIT_COLORIZE | DSBLIT_SRC_COLORKEY );
          primary->SetColor( primary, 0x20, 0x40, 0x40, 0xff );
     }

     primary->Blit( primary, cardicon,
                    NULL, ui_fontheight/4, SH + ui_fontheight/10 );

     return (mask & func) ? true : !accel_only;
}

/**************************************************************************************************/

static unsigned long long draw_string( long t )
{
     long i;

     dest->SetDrawingFlags( dest, DSDRAW_NOFX );

     if (!showAccelerated( DFXL_DRAWSTRING, NULL ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          dest->SetColor( dest,
                          myrand()&0xFF, myrand()&0xFF, myrand()&0xFF, 0xFF );
          dest->DrawString( dest,
                            "DirectX is dead, this is DirectFB!!!", -1,
                            myrand() % (SW-stringwidth),
                            myrand() % (SH-bench_fontheight),
                            DSTF_TOPLEFT );
     }
     return 1000*36*(unsigned long long)i;
}

static unsigned long long draw_string_blend( long t )
{
     long i;

     dest->SetDrawingFlags( dest, DSDRAW_BLEND );

     if (!showAccelerated( DFXL_DRAWSTRING, NULL ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          dest->SetColor( dest,
                          myrand()&0xFF, myrand()&0xFF, myrand()&0xFF,
                          myrand()%0x64 );
          dest->DrawString( dest,
                            "DirectX is dead, this is DirectFB!!!", -1,
                            myrand() % (SW-stringwidth),
                            myrand() % (SH-bench_fontheight),
                            DSTF_TOPLEFT );
     }
     return 1000*36*(unsigned long long)i;
}

static unsigned long long fill_rect( long t )
{
     long i;

     dest->SetDrawingFlags( dest, DSDRAW_NOFX );

     if (!showAccelerated( DFXL_FILLRECTANGLE, NULL ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          dest->SetColor( dest,
                          myrand()&0xFF, myrand()&0xFF, myrand()&0xFF, 0xFF );
          dest->FillRectangle( dest,
                               myrand()%(SW-SX), myrand()%(SH-SY), SX, SY );
     }
     return SX*SY*(unsigned long long)i;
}

static unsigned long long fill_rect_blend( long t )
{
     long i;

     dest->SetDrawingFlags( dest, DSDRAW_BLEND );

     if (!showAccelerated( DFXL_FILLRECTANGLE, NULL ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          dest->SetColor( dest, myrand()&0xFF, myrand()&0xFF, myrand()&0xFF, myrand()%0x64 );
          dest->FillRectangle( dest, myrand()%(SW-SX), myrand()%(SH-SY), SX, SY );
     }
     return SX*SY*(unsigned long long)i;
}

static unsigned long long fill_rects( long t )
{
     long i, l;
     DFBRectangle rects[10];

     dest->SetDrawingFlags( dest, DSDRAW_NOFX );

     if (!showAccelerated( DFXL_FILLRECTANGLE, NULL ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          for (l=0; l<10; l++) {
               rects[l].x = myrand()%(SW-SX);
               rects[l].y = myrand()%(SH-SY);
               rects[l].w = SX;
               rects[l].h = SY;
          }

          dest->SetColor( dest, myrand()&0xFF, myrand()&0xFF, myrand()&0xFF, 0xFF );
          dest->FillRectangles( dest, rects, 10 );
     }

     return SX*SY*10*(unsigned long long)i;
}

static unsigned long long fill_rects_blend( long t )
{
     long i, l;
     DFBRectangle rects[10];

     dest->SetDrawingFlags( dest, DSDRAW_BLEND );

     if (!showAccelerated( DFXL_FILLRECTANGLE, NULL ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          for (l=0; l<10; l++) {
               rects[l].x = myrand()%(SW-SX);
               rects[l].y = myrand()%(SH-SY);
               rects[l].w = SX;
               rects[l].h = SY;
          }

          dest->SetColor( dest, myrand()&0xFF, myrand()&0xFF, myrand()&0xFF, myrand()%0x64 );
          dest->FillRectangles( dest, rects, 10 );
     }

     return SX*SY*10*(unsigned long long)i;
}

static unsigned long long fill_triangle( long t )
{
     long i, x, y;

     dest->SetDrawingFlags( dest, DSDRAW_NOFX );

     if (!showAccelerated( DFXL_FILLTRIANGLE, NULL ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          x = myrand()%(SW-SX);
          y = myrand()%(SH-SY);

          dest->SetColor( dest,
                          myrand()&0xFF, myrand()&0xFF, myrand()&0xFF, 0xFF );
          dest->FillTriangle( dest, x, y, x+SX-1, y+SY/2, x, y+SY-1 );
     }
     return SX*SY*(unsigned long long)i/2;
}

static unsigned long long fill_triangle_blend( long t )
{
     long i, x, y;

     dest->SetDrawingFlags( dest, DSDRAW_BLEND );

     if (!showAccelerated( DFXL_FILLTRIANGLE, NULL ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          x = myrand()%(SW-SX);
          y = myrand()%(SH-SY);

          dest->SetColor( dest,
                          myrand()&0xFF, myrand()&0xFF, myrand()&0xFF,
                          myrand()%0x64 );
          dest->FillTriangle( dest, x, y, x+SX-1, y+SY/2, x, y+SY-1 );
     }
     return SX*SY*(unsigned long long)i/2;
}

static unsigned long long draw_rect( long t )
{
     long i;

     dest->SetDrawingFlags( dest, DSDRAW_NOFX );

     if (!showAccelerated( DFXL_DRAWRECTANGLE, NULL ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          dest->SetColor( dest,
                          myrand()&0xFF, myrand()&0xFF, myrand()&0xFF, 0xFF );
          dest->DrawRectangle( dest,
                               myrand()%(SW-SX), myrand()%(SH-SY), SX, SY );
     }
     return 1000*(unsigned long long)i;
}

static unsigned long long draw_rect_blend( long t )
{
     long i;

     dest->SetDrawingFlags( dest, DSDRAW_BLEND );

     if (!showAccelerated( DFXL_DRAWRECTANGLE, NULL ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          dest->SetColor( dest,
                          myrand()&0xFF, myrand()&0xFF, myrand()&0xFF,
                          myrand()%0x64 );
          dest->DrawRectangle( dest,
                               myrand()%(SW-SX), myrand()%(SH-SY), SX, SY );
     }
     return 1000*(unsigned long long)i;
}

static unsigned long long draw_lines( long t )
{
     long i, l, x, y, dx, dy;
     DFBRegion lines[10];

     dest->SetDrawingFlags( dest, DSDRAW_NOFX );

     if (!showAccelerated( DFXL_DRAWLINE, NULL ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {

          for (l=0; l<10; l++) {
               x  = myrand() % (SW-SX) + SX/2;
               y  = myrand() % (SH-SY) + SY/2;
               dx = myrand() % (2*SX) - SX;
               dy = myrand() % (2*SY) - SY;

               lines[l].x1 = x - dx/2;
               lines[l].y1 = y - dy/2;
               lines[l].x2 = x + dx/2;
               lines[l].y2 = y + dy/2;
          }

          dest->SetColor( dest,
                          myrand()&0xFF, myrand()&0xFF, myrand()&0xFF, 0xFF );
          dest->DrawLines( dest, lines, 10 );
     }
     return 1000*10*(unsigned long long)i;
}

static unsigned long long draw_lines_blend( long t )
{
     long i, l, x, y, dx, dy;
     DFBRegion lines[10];

     dest->SetDrawingFlags( dest, DSDRAW_BLEND );

     if (!showAccelerated( DFXL_DRAWLINE, NULL ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {

          for (l=0; l<10; l++) {
               x  = myrand() % (SW-SX) + SX/2;
               y  = myrand() % (SH-SY) + SY/2;
               dx = myrand() % (2*SX) - SX;
               dy = myrand() % (2*SY) - SY;

               lines[l].x1 = x - dx/2;
               lines[l].y1 = y - dy/2;
               lines[l].x2 = x + dx/2;
               lines[l].y2 = y + dy/2;
          }

          dest->SetColor( dest,
                          myrand()&0xFF, myrand()&0xFF, myrand()&0xFF,
                          myrand()%0x64 );
          dest->DrawLines( dest, lines, 10 );
     }
     return 1000*10*(unsigned long long)i;
}

static unsigned long long fill_spans_with_flags( long t, DFBSurfaceDrawingFlags flags )
{
     long    i;
     DFBSpan spans[SY];

     dest->SetDrawingFlags( dest, flags );

     if (!showAccelerated( DFXL_FILLRECTANGLE, NULL ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          int w = myrand() % 25 + 5;
          int x = myrand() % (SW-SX-w*2) + w;
          int d = 0;
          int a = 1;
          int l;

          for (l=0; l<SY; l++) {
               spans[l].x = x + d;
               spans[l].w = SX;

               d += a;

               if (d == w)
                    a = -1;
               else if (d == -w)
                    a = 1;
          }

          dest->SetColor( dest, myrand()&0xFF, myrand()&0xFF, myrand()&0xFF,
                          (flags & DSDRAW_BLEND) ? myrand()%0x64 : 0xff );
          dest->FillSpans( dest, myrand() % (SH-SY), spans, SY );
     }

     return SX * SY * (unsigned long long) i;
}

static unsigned long long fill_spans( long t )
{
     return fill_spans_with_flags( t, DSDRAW_NOFX );
}

static unsigned long long fill_spans_blend( long t )
{
     return fill_spans_with_flags( t, DSDRAW_BLEND );
}


static unsigned long long blit( long t )
{
     long i;

     dest->SetBlittingFlags( dest, DSBLIT_NOFX );

     if (!showAccelerated( DFXL_BLIT, simple ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          dest->Blit( dest, simple, NULL,
                      (SW!=SX) ? myrand() % (SW-SX) : 0,
                      (SH-SY)  ? myrand() % (SH-SY) : 0 );
     }
     return SX*SY*(unsigned long long)i;
}

static unsigned long long blit180( long t )
{
     long i;

     dest->SetBlittingFlags( dest, DSBLIT_ROTATE180 );

     if (!showAccelerated( DFXL_BLIT, simple ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          dest->Blit( dest, simple, NULL,
                      (SW!=SX) ? myrand() % (SW-SX) : 0,
                      (SH-SY)  ? myrand() % (SH-SY) : 0 );
     }
     return SX*SY*(unsigned long long)i;
}


static unsigned long long blit_dst_colorkeyed( long t )
{
     long i;
     DFBRegion clip;

     clip.x1 = 0;
     clip.x2 = SW-1;
     clip.y1 = 0;
     clip.y2 = SH-1;

     dest->SetClip( dest, &clip );
     dest->SetBlittingFlags( dest, DSBLIT_NOFX );
     dest->TileBlit( dest, logo, NULL, 0, 0 );
     dest->SetClip( dest, NULL );

     dest->SetBlittingFlags( dest, DSBLIT_DST_COLORKEY );
     dest->SetDstColorKey( dest, 0xFF, 0xFF, 0xFF );

     if (!showAccelerated( DFXL_BLIT, simple ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          dest->Blit( dest, simple, NULL,
                      (SW!=SX) ? myrand() % (SW-SX) : 0,
                      (SY-SH)  ? myrand() % (SH-SY) : 0 );
     }
     return SX*SY*(unsigned long long)i;
}

static unsigned long long blit_colorkeyed( long t )
{
     long i;

     dest->SetBlittingFlags( dest, DSBLIT_SRC_COLORKEY );

     if (!showAccelerated( DFXL_BLIT, colorkeyed ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          dest->Blit( dest, colorkeyed, NULL,
                      (SW!=SX) ? myrand() % (SW-SX) : 0,
                      (SY-SH)  ? myrand() % (SH-SY) : 0 );
     }
     return SX*SY*(unsigned long long)i;
}

static unsigned long long blit_convert( long t )
{
     long i;

     dest->SetBlittingFlags( dest, DSBLIT_NOFX );

     if (!showAccelerated( DFXL_BLIT, image32 ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          dest->Blit( dest, image32, NULL,
                      (SW!=SX) ? myrand() % (SW-SX) : 0,
                      (SY-SH)  ? myrand() % (SH-SY) : 0 );
     }
     return SX*SY*(unsigned long long)i;
}

static unsigned long long blit_colorize( long t )
{
     long i;

     dest->SetBlittingFlags( dest, DSBLIT_COLORIZE );

     if (!showAccelerated( DFXL_BLIT, simple ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          dest->SetColor( dest, myrand()&0xFF, myrand()&0xFF, myrand()&0xFF, 0xff );

          dest->Blit( dest, simple, NULL,
                      (SW!=SX) ? myrand() % (SW-SX) : 0,
                      (SY-SH)  ? myrand() % (SH-SY) : 0 );
     }
     return SX*SY*(unsigned long long)i;
}

static unsigned long long blit_lut( long t )
{
     long i;

     dest->SetBlittingFlags( dest, DSBLIT_NOFX );

     if (!showAccelerated( DFXL_BLIT, image_lut ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          dest->Blit( dest, image_lut, NULL,
                      (SW!=SX) ? myrand() % (SW-SX) : 0,
                      (SY-SH)  ? myrand() % (SH-SY) : 0 );
     }
     return SX*SY*(unsigned long long)i;
}

static unsigned long long blit_lut_blend( long t )
{
     long i;

     dest->SetBlittingFlags( dest, DSBLIT_BLEND_ALPHACHANNEL );

     if (!showAccelerated( DFXL_BLIT, image_lut ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          dest->Blit( dest, image_lut, NULL,
                      (SW!=SX) ? myrand() % (SW-SX) : 0,
                      (SY-SH)  ? myrand() % (SH-SY) : 0 );
     }
     return SX*SY*(unsigned long long)i;
}

static unsigned long long blit_blend( long t )
{
     long i;

     dest->SetBlittingFlags( dest, DSBLIT_BLEND_ALPHACHANNEL );

     if (!showAccelerated( DFXL_BLIT, image32a ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          dest->Blit( dest, image32a, NULL,
                      (SW!=SX) ? myrand() % (SW-SX) : 0,
                      (SY-SH)  ? myrand() % (SH-SY) : 0 );
     }
     return SX*SY*(unsigned long long)i;
}

static unsigned long long blit_blend_colorize( long t )
{
     long i;

     dest->SetBlittingFlags( dest, DSBLIT_COLORIZE | DSBLIT_BLEND_ALPHACHANNEL );

     if (!showAccelerated( DFXL_BLIT, image32a ))
          return 0;

     for (i=0; i%100 || myclock()<(t+DEMOTIME); i++) {
          dest->SetColor( dest, myrand()&0xFF, myrand()&0xFF, myrand()&0xFF, 0xff );

          dest->Blit( dest, image32a, NULL,
                      (SW!=SX) ? myrand() % (SW-SX) : 0,
                      (SY-SH)  ? myrand() % (SH-SY) : 0 );
     }
     return SX*SY*(unsigned long long)i;
}

static unsigned long long stretch_blit( long t )
{
     long i, j;
     unsigned long long pixels = 0;

     dest->SetBlittingFlags( dest, DSBLIT_NOFX );

     if (!showAccelerated( DFXL_STRETCHBLIT, simple ))
          return 0;

     for (j=1; myclock()<(t+DEMOTIME); j++) {
          if (j>SH) {
               j = 10;
          }
          for (i=10; i<SH; i+=j) {
               DFBRectangle dr = { SW/2-i/2, SH/2-i/2, i, i };

               dest->StretchBlit( dest, simple, NULL, &dr );

               pixels += dr.w * dr.h;
          }
     }
     return pixels;
}

static unsigned long long stretch_blit_colorkeyed( long t )
{
     long i, j;
     unsigned long long pixels = 0;

     dest->SetBlittingFlags( dest, DSBLIT_SRC_COLORKEY );

     if (!showAccelerated( DFXL_STRETCHBLIT, simple ))
          return 0;

     for (j=1; myclock()<(t+DEMOTIME); j++) {
          if (j>SH) {
               j = 10;
          }
          for (i=10; i<SH; i+=j) {
               DFBRectangle dr = { SW/2-i/2, SH/2-i/2, i, i };

               dest->StretchBlit( dest, colorkeyed, NULL, &dr );

               pixels += dr.w * dr.h;
          }
     }
     return pixels;
}

static unsigned long long stretch_blit_ycbcr( long t )
{
     long i, j;
     unsigned long long pixels = 0;

     dest->SetBlittingFlags( dest, DSBLIT_NOFX );

     showAccelerated( DFXL_STRETCHBLIT, simple_ycbcr );

     for (j=1; myclock()<(t+DEMOTIME); j++) {
          if (j>SH) {
               j = 10;
          }
          for (i=10; i<SH; i+=j) {
               DFBRectangle dr = { SW/2-i/2, SH/2-i/2, i, i };

               dest->StretchBlit( dest, simple_ycbcr, NULL, &dr );

               pixels += dr.w * dr.h;
          }
     }
     return pixels;
}

static unsigned long long stretch_blit_indexed( long t )
{
     long i, j;
     unsigned long long pixels = 0;

     dest->SetBlittingFlags( dest, DSBLIT_NOFX );

     if (!showAccelerated( DFXL_STRETCHBLIT, image_lut ))
          return 0;

     for (j=1; myclock()<(t+DEMOTIME); j++) {
          if (j>SH) {
               j = 10;
          }
          for (i=10; i<SH; i+=j) {
               DFBRectangle dr = { SW/2-i/2, SH/2-i/2, i, i };

               dest->StretchBlit( dest, image_lut, NULL, &dr );

               pixels += dr.w * dr.h;
          }
     }
     return pixels;
}

static unsigned long long common_load_image( long t, const char *filename )
{
     DFBResult              err;
     int                    i;
     IDirectFBSurface      *surface = NULL;
     DFBSurfaceDescription  dsc;

     for (i=0; myclock()<(t+DEMOTIME); i++) {
          IDirectFBImageProvider *provider;

          /* create a surface and render an image to it */
          DFBCHECK(dfb->CreateImageProvider( dfb, filename, &provider ));
          DFBCHECK(provider->GetSurfaceDescription( provider, &dsc ));
          if (!surface)
               DFBCHECK(dfb->CreateSurface( dfb, &dsc, &surface ));
          DFBCHECK(provider->RenderTo( provider, surface, NULL ));
          DFBCHECK(provider->Release( provider ));
     }

     if (surface)
          DFBCHECK(surface->Release( surface ));

     snprintf( current_demo->desc, sizeof(current_demo->desc), "%s (%dx%d %s)",
               current_demo->desc, dsc.width, dsc.height, dfb_pixelformat_name(dsc.pixelformat) );

     return i * dsc.width * dsc.height;
}

static unsigned long long load_dfiff( long t )
{
     DFBSurfacePixelFormat format;

     dest->GetPixelFormat( dest, &format );

     if (DFB_BYTES_PER_PIXEL(format) > 2)
          return common_load_image( t, DATADIR"/melted_rgb32.dfiff" );

     return common_load_image( t, DATADIR"/melted_rgb16.dfiff" );
}

static unsigned long long load_gif( long t )
{
     return common_load_image( t, DATADIR"/melted.gif" );
}

static unsigned long long load_jpeg( long t )
{
     return common_load_image( t, DATADIR"/melted.jpg" );
}

static unsigned long long load_png( long t )
{
     return common_load_image( t, DATADIR"/melted.png" );
}

static unsigned long long load_image( long t )
{
     return common_load_image( t, imagefile );
}

/**************************************************************************************************/

DirectFBPixelFormatNames(format_strings)
#define NUM_FORMAT_STRINGS (sizeof(format_strings) / sizeof(format_strings[0]))

static DFBSurfacePixelFormat
parse_pixelformat( const char *format )
{
     int i;

     for (i = 0; i < NUM_FORMAT_STRINGS; i++) {
          if (!strcmp( format, format_strings[i].name ))
               return format_strings[i].format;
     }

     return DSPF_UNKNOWN;
}

/**************************************************************************************************/

int main( int argc, char *argv[] )
{
     DFBResult err;
     DFBSurfacePixelFormat pixelformat = DSPF_UNKNOWN;
     DFBSurfaceDescription dsc;
     DFBSurfaceRenderOptions render_options = DSRO_NONE;
     DFBImageDescription image_dsc;
     int i, n;
     int demo_requested = 0;

     DFBCHECK(DirectFBInit( &argc, &argv ));

     /* parse command line */
     for (n = 1; n < argc; n++) {
          if (strncmp (argv[n], "--", 2) == 0) {
               for (i = 0; i < num_demos; i++) {
                    if (strcmp (argv[n] + 2, demos[i].option) == 0) {
                         demo_requested = 1;
                         demos[i].requested = 1;
                         break;
                    }
               }
               if (i == num_demos) {
                    if (strcmp (argv[n] + 2, "help") == 0) {
                         print_usage();
                         return EXIT_SUCCESS;
                    }
                    else
                    if (strcmp (argv[n] + 2, "noresults") == 0) {
                         show_results = 0;
                         continue;
                    }
                    else
                    if (strcmp (argv[n] + 2, "system") == 0) {
                         do_system = 1;
                         do_offscreen = 1;
                         continue;
                    }
                    else
                    if (strcmp (argv[n] + 2, "offscreen") == 0) {
                         do_offscreen = 1;
                         continue;
                    }
                    else
                    if (strcmp (argv[n] + 2, "noaccel") == 0) {
                         do_noaccel = 1;
                         continue;
                    }
                    else
                    if (strcmp (argv[n] + 2, "accelonly") == 0) {
                         accel_only = 1;
                         continue;
                    }
                    else
                    if (strcmp (argv[n] + 2, "dump") == 0) {
                         do_dump = 1;
                         continue;
                    }
                    else
                    if (strcmp (argv[n] + 2, "aa") == 0) {
                         do_aa = 1;
                         continue;
                    }
                    else
                    if (strcmp (argv[n] + 2, "matrix") == 0) {
                         do_matrix = 1;
                         continue;
                    }
                    else
                    if (strcmp (argv[n] + 2, "smooth") == 0) {
                         do_smooth = 1;
                         continue;
                    }
                    else
                    if (strcmp (argv[n] + 2, "mono") == 0) {
                         mono_fonts = 1;
                         direct_snputs( demos[DEMO_DRAWSTRING].desc, "Monochrome Text",
                                        sizeof(demos[DEMO_DRAWSTRING].desc) );
                         demos[DEMO_DRAWSTRING].status = "Monochrome Text";
                         direct_snputs( demos[DEMO_DRAWSTRING_BLEND].desc, "Monochrome Text (blend)",
                                        sizeof(demos[DEMO_DRAWSTRING].desc) );
                         demos[DEMO_DRAWSTRING_BLEND].status = "Alpha Blended Monochrome Text";
                         continue;
                    }
                    else
                    if (strcmp (argv[n] + 2, "size") == 0 &&
                        ++n < argc &&
                        sscanf (argv[n], "%dx%d", &SX, &SY) == 2) {
                         continue;
                    }
                    else
                    if (strcmp (argv[n] + 2, "duration") == 0 &&
                        ++n < argc &&
                        sscanf (argv[n], "%d", &DEMOTIME) == 1) {
                         continue;
                    }
                    else
                    if (strcmp (argv[n] + 2, "font") == 0 &&
                        ++n < argc && argv[n]) {
                         fontfile = argv[n];
                         continue;
                    }
                    else
                    if (strcmp (argv[n] + 2, "load-image") == 0 &&
                        ++n < argc && argv[n]) {
                         imagefile = argv[n];
                         demo_requested = 1;
                         demos[DEMO_LOAD_IMAGE].requested = 1;
                         continue;
                    }
                    else
                    if (strcmp (argv[n] + 2, "pixelformat") == 0 &&
                        ++n < argc && argv[n]) {
                         pixelformat = parse_pixelformat( argv[n] );
                         continue;
                    }
               }
               else {
                    continue;
               }
          }

          print_usage();
          return EXIT_FAILURE;
     }
     if (!demo_requested) {
          for (i = 0; i < num_demos; i++) {
               demos[i].requested = demos[i].default_on;
          }
     }

     DirectFBSetOption ("bg-none", NULL);

     /* create the super interface */
     DFBCHECK(DirectFBCreate( &dfb ));

     /* create an input buffer for key events */
     DFBCHECK(dfb->CreateInputEventBuffer( dfb, DICAPS_KEYS,
                                           DFB_FALSE, &key_events ));

     /* Set the cooperative level to DFSCL_FULLSCREEN for exclusive access to the primary layer. */
     err = dfb->SetCooperativeLevel( dfb, DFSCL_FULLSCREEN );
     if (err)
          DirectFBError( "Failed to get exclusive access", err );

     /* Get the primary surface, i.e. the surface of the primary layer. */
     dsc.flags = DSDESC_CAPS;
     dsc.caps = DSCAPS_PRIMARY;

     DFBCHECK(dfb->CreateSurface( dfb, &dsc, &primary ));

     if (pixelformat == DSPF_UNKNOWN)
          primary->GetPixelFormat( primary, &pixelformat );

     primary->GetSize( primary, &SW, &SH );
     primary->Clear( primary, 0, 0, 0, 0x80 );

     if (do_offscreen) {
          dsc.flags = DSDESC_WIDTH | DSDESC_HEIGHT | DSDESC_PIXELFORMAT | DSDESC_CAPS;
          dsc.width = SW;
          dsc.height = SH;
          dsc.pixelformat = pixelformat;
          dsc.caps = do_system ? DSCAPS_SYSTEMONLY : DSCAPS_VIDEOONLY;

          DFBCHECK(dfb->CreateSurface( dfb, &dsc, &dest ));

          dest->Clear( dest, 0, 0, 0, 0x80 );
     }
     else {
          DFBRectangle rect = { 0, 0, SW, SH };

          primary->GetSubSurface (primary, &rect, &dest);
     }

     if (do_noaccel)
          dest->DisableAcceleration( dest, DFXL_ALL );

     {
          DFBCHECK(dfb->CreateImageProvider( dfb, DATADIR"/biglogo.png",
                                             &provider ));
          DFBCHECK(provider->GetSurfaceDescription( provider, &dsc ));

          dsc.width  = (SH / 8) * dsc.width / dsc.height;
          dsc.height = SH / 8;

          DFBCHECK(dfb->CreateSurface( dfb, &dsc, &logo ));
          DFBCHECK(provider->RenderTo( provider, logo, NULL ));
          provider->Release( provider );

          primary->SetBlittingFlags( primary, DSBLIT_BLEND_ALPHACHANNEL );
          primary->Blit( primary, logo, NULL, (SW - dsc.width) / 2, SH / 5 );
     }

     {
          DFBFontDescription desc;

          desc.flags      = DFDESC_HEIGHT | DFDESC_ATTRIBUTES;
          desc.height     = 22;
          desc.attributes = mono_fonts ? DFFA_MONOCHROME : DFFA_NONE;

          DFBCHECK(dfb->CreateFont( dfb, fontfile, &desc, &bench_font ));

          bench_font->GetHeight( bench_font, &bench_fontheight );

          bench_font->GetStringWidth( bench_font,
                                      "DirectX is dead, this is DirectFB!!!", -1,
                                      &stringwidth );

          dest->SetFont( dest, bench_font );
     }

     primary->SetFont( primary, bench_font );
     primary->SetColor( primary, 0xA0, 0xA0, 0xA0, 0xFF );
     primary->DrawString( primary, "Preparing...", -1,
                          SW / 2, SH / 2, DSTF_CENTER );

     primary->Flip( primary, NULL, 0);

     {
          DFBFontDescription desc;

          desc.flags      = DFDESC_HEIGHT | DFDESC_ATTRIBUTES;
          desc.height     = 1 + 24 * SH / 1024;
          desc.attributes = mono_fonts ? DFFA_MONOCHROME : DFFA_NONE;

          DFBCHECK(dfb->CreateFont( dfb, fontfile, &desc, &ui_font ));

          ui_font->GetHeight( ui_font, &ui_fontheight );

          primary->SetFont( primary, ui_font );
     }

     SH -= ui_fontheight;

     if (SX > SW - 10)
          SX = SW - 10;
     if (SY > SH - 10)
          SY = SH - 10;

     /* create a surface and render an image to it */
     DFBCHECK(dfb->CreateImageProvider( dfb, DATADIR"/card.png", &provider ));
     DFBCHECK(provider->GetSurfaceDescription( provider, &dsc ));
     dsc.width  = dsc.width * (ui_fontheight - ui_fontheight/5) / dsc.height;
     dsc.height = (ui_fontheight - ui_fontheight/5);
     DFBCHECK(dfb->CreateSurface( dfb, &dsc, &cardicon ));
     DFBCHECK(provider->RenderTo( provider, cardicon, NULL ));
     provider->Release( provider );

     /* create a surface and render an image to it */
     DFBCHECK(dfb->CreateImageProvider( dfb, DATADIR"/melted.png",
                                        &provider ));
     DFBCHECK(provider->GetSurfaceDescription( provider, &dsc ));

     dsc.flags = DSDESC_WIDTH | DSDESC_HEIGHT | DSDESC_PIXELFORMAT;
     dsc.width = SX;
     dsc.height = SY;
     dsc.pixelformat = pixelformat;

     DFBCHECK(dfb->CreateSurface( dfb, &dsc, &simple ));
     DFBCHECK(provider->RenderTo( provider, simple, NULL ));
     
     dsc.flags |= DSDESC_PIXELFORMAT;
     dsc.pixelformat = DSPF_YUY2;
     
     DFBCHECK(dfb->CreateSurface( dfb, &dsc, &simple_ycbcr ));
     DFBCHECK(provider->RenderTo( provider, simple_ycbcr, NULL ));
     
     provider->Release( provider );

     /* create a surface and render an image to it */

     DFBCHECK(dfb->CreateImageProvider( dfb, DATADIR"/colorkeyed.gif",
                                        &provider ));
     DFBCHECK(provider->GetSurfaceDescription( provider, &dsc ));

     dsc.flags = DSDESC_WIDTH | DSDESC_HEIGHT | DSDESC_PIXELFORMAT;
     dsc.width = SX;
     dsc.height = SY;
     dsc.pixelformat = pixelformat;

     DFBCHECK(dfb->CreateSurface( dfb, &dsc, &colorkeyed ));
     DFBCHECK(provider->RenderTo( provider, colorkeyed, NULL ));

     provider->GetImageDescription( provider, &image_dsc);

     if (image_dsc.caps & DICAPS_COLORKEY)
          colorkeyed->SetSrcColorKey( colorkeyed,
                                      image_dsc.colorkey_r,
                                      image_dsc.colorkey_g,
                                      image_dsc.colorkey_b );

     provider->Release( provider );

     /* create a surface and render an image to it */
     DFBCHECK(dfb->CreateImageProvider( dfb, DATADIR"/pngtest.png",
                                        &provider ));
     DFBCHECK(provider->GetSurfaceDescription( provider, &dsc ));

     dsc.flags = DSDESC_WIDTH | DSDESC_HEIGHT | DSDESC_PIXELFORMAT;
     dsc.width = SX;
     dsc.height = SY;
     dsc.pixelformat = DFB_BYTES_PER_PIXEL(pixelformat) == 2 ?
                       DSPF_RGB32 : DSPF_RGB16;

     DFBCHECK(dfb->CreateSurface( dfb, &dsc, &image32 ));
     DFBCHECK(provider->RenderTo( provider, image32, NULL ));
     provider->Release( provider );

     /* create a surface and render an image to it */
     dsc.flags = DSDESC_WIDTH | DSDESC_HEIGHT | DSDESC_PIXELFORMAT;
     dsc.width = SX;
     dsc.height = SY;
     dsc.pixelformat = DSPF_ARGB;

     DFBCHECK(dfb->CreateSurface( dfb, &dsc, &image32a ));
     DFBCHECK(dfb->CreateImageProvider( dfb, DATADIR"/pngtest2.png",
                                        &provider ));
     DFBCHECK(provider->RenderTo( provider, image32a, NULL ));
     provider->Release( provider );

     /* create a surface and render an image to it */
     {
          IDirectFBSurface *tmp;
          IDirectFBPalette *palette;

          DFBCHECK(dfb->CreateSurface( dfb, &pngtest3_png_desc, &tmp ));

          DFBCHECK(tmp->GetPalette( tmp, &palette ));

          dsc.flags = DSDESC_WIDTH | DSDESC_HEIGHT | DSDESC_PIXELFORMAT;
          dsc.width = SX;
          dsc.height = SY;
          dsc.pixelformat = DSPF_LUT8;

          DFBCHECK(dfb->CreateSurface( dfb, &dsc, &image_lut ));

          DFBCHECK(image_lut->SetPalette( image_lut, palette ));

          image_lut->StretchBlit( image_lut, tmp, NULL, NULL );

          palette->Release( palette );
          tmp->Release( tmp );
     }

     if (with_intro) {
          /* create a surface and render an image to it */
          DFBCHECK(dfb->CreateImageProvider( dfb, DATADIR"/intro.png",
                                             &provider ));
          DFBCHECK(provider->GetSurfaceDescription( provider, &dsc ));

          dsc.width = SW;
          dsc.height = SH + ui_fontheight;

          DFBCHECK(dfb->CreateSurface( dfb, &dsc, &intro ));

          DFBCHECK(provider->RenderTo( provider, intro, NULL ));
          provider->Release( provider );
     }


     printf( "\nBenchmarking %dx%d on %dx%d %s (%dbit)...\n\n",
             SX, SY, SW, SH, dfb_pixelformat_name(pixelformat),
             DFB_BYTES_PER_PIXEL(pixelformat) * 8 );

     sync();

     if (do_matrix) {
          const s32 matrix[6] = { 0x01000, 0x19f00, 0x00000,
                                  0x08a00, 0x01000, 0x00000 };

          dest->SetMatrix( dest, matrix );

          render_options |= DSRO_MATRIX;
     }

     if (do_aa)
          render_options |= DSRO_ANTIALIAS;

     if (do_smooth)
          render_options |= DSRO_SMOOTH_UPSCALE | DSRO_SMOOTH_DOWNSCALE;

     dest->SetRenderOptions( dest, render_options );

     for (i = 0; i < num_demos; i++) {
           int ticks, load;
           long t, dt;
           unsigned long long pixels;
           struct tms tms1, tms2;

           if (!demos[i].requested)
                continue;

           current_demo = &demos[i];

           showMessage( demos[i].message );
           showStatus( demos[i].status );

           /* Get ready... */
           sync();
           dfb->WaitIdle( dfb );

           /* Take start... */
           times(&tms1);
           t = myclock();

           /* GO! */
           pixels = (* demos[i].func)(t);

           /* Wait... */
           dfb->WaitIdle( dfb );

           /* Take stop... */
           dt = myclock() - t;
           times(&tms2);

           if (!pixels || !dt)
                continue;

           primary->Flip( primary, NULL, 0 );

           /* Calculate 1000s per second. */
           demos[i].result = pixels / (unsigned long long)dt;

           /* Calculate CPU load caused by user/kernel space,
            * but without interrupt load that might be blitter related. */
           ticks = tms2.tms_utime - tms1.tms_utime + tms2.tms_stime - tms1.tms_stime;
           load  = ticks * 1000 / (sysconf(_SC_CLK_TCK) * dt / 1000);

           printf( "%s%s%-44s %3ld.%.3ld secs (%s%4ld.%.3ld %s) [%3d.%d%%]\n",
                   do_aa ? "AA " : "",
                   do_matrix ? "MX " : "",
                   demos[i].desc, dt / 1000, dt % 1000,
                   demos[i].accelerated ? "*" : " ",
                   demos[i].result / 1000,
                   demos[i].result % 1000, demos[i].unit, load / 10, load % 10 );
           if (do_offscreen) {
                primary->SetBlittingFlags (primary, DSBLIT_NOFX);
                primary->Blit( primary, dest, NULL, 0, 0);
                sleep(2);
                dest->Clear( dest, 0, 0, 0, 0x80 );
           }
           if (do_dump)
                primary->Dump( primary, ".", "df_dok" );
     }

     if (show_results)
          showResult();

     printf( "\n" );

     shutdown();

     return EXIT_SUCCESS;
}

