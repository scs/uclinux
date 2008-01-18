/*
   (c) Copyright 2000-2002  convergence integrated media GmbH.
   All rights reserved.

   Written by Denis Oliver Kropp <dok@directfb.org>,
              Andreas Hundt <andi@fischlustig.de> and
              Sven Neumann <neo@directfb.org>.

   df_fonts written by Holger Waechtler <holger@convergence.de>

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <direct/types.h>

#include <directfb.h>


/* macro for a safe call to DirectFB functions */
#define DFBCHECK(x...)                                           \
do {                                                             \
     int err = x;                                                \
     if (err != DFB_OK) {                                        \
          fprintf( stderr, "%s <%d>:\n\t", __FILE__, __LINE__ ); \
          DirectFBErrorFatal( #x, err );                         \
     }                                                           \
} while (0)


#define ERROR(x...)                                              \
do {                                                             \
     fprintf (stderr, "%s <%i>: ", __FILE__, __LINE__);          \
        fprintf (stderr, x);                                     \
        fprintf (stderr, "\n");                                  \
     exit (-1);                                                  \
} while (0)


static char **fontname_list;
static int fontname_count;

static IDirectFB             *dfb;
static IDirectFBEventBuffer  *keybuffer;
static IDirectFBDisplayLayer *layer;
static IDirectFBSurface      *surface;

static int show_help         = 0;
static int show_ascender     = 0;
static int show_descender    = 0;
static int show_baseline     = 0;
static int show_glyphrect    = 0;
static int show_glyphadvance = 0;
static int show_glyphorigin  = 0;

static int antialias         = 1;
static int unicode_mode      = 1;

static int glyphs_per_xline  = 16;
static int glyphs_per_yline  = 16;


#define GLYPHS_PER_PAGE (glyphs_per_xline * glyphs_per_yline)


static const struct {
     char *key;
     char *description;
} key_description [] = {
     { "PGUP",       "Page up"},
     { "PGDOWN",     "Page down"},
     { "A",          "show/hide Ascender"},
     { "D",          "show/hide Descender"},
     { "B",          "show/hide Baseline"},
     { "R",          "show/hide Glyph Rectangle"},
     { "G",          "show/hide Glyph Advance"},
     { "O",          "show/hide Glyph Origin"},
     { "SPC/UP",     "next Font"},
     { "BKSPC/DOWN", "prev Font"},
     { "PLUS",       "more Glyphs per Page"},
     { "MINUS",      "less Glyphs per Page"},
     { "U",          "toggle Unicode/Raw Glyph Map"},
     { "M",          "enable/disable Antialiasing"},
     { "F1",         "Help"},
     { "ESC",        "Exit"}
};

#define N_KEY_DESC (int)((sizeof(key_description) / sizeof(key_description[0])))


static void
render_help_page (IDirectFBSurface *surface)
{
     DFBFontDescription fontdesc;
     IDirectFBFont *fixedfont;
     int width, height;
     int i;

     surface->GetSize (surface, &width, &height);

     fontdesc.flags = DFDESC_ATTRIBUTES;
     fontdesc.attributes = antialias ? 0 : DFFA_MONOCHROME;

     DFBCHECK(dfb->CreateFont (dfb, NULL, &fontdesc, &fixedfont));
     surface->SetColor (surface, 0x00, 0x00, 0x00, 0xff);
     surface->SetFont (surface, fixedfont);

     for (i=0; i<N_KEY_DESC; i++) {
          int x = 150 + (i / ((N_KEY_DESC+1)/2)) * (width - 100) / 2;
          int y = 60 + (i % ((N_KEY_DESC+1)/2)) * 25;

          surface->DrawString (surface,
                               key_description[i].key, -1,
                               x - 10, y, DSTF_RIGHT);

          surface->DrawString (surface,
                               key_description[i].description, -1,
                               x + 10, y, DSTF_LEFT);
     }

     surface->DrawString (surface, "Loaded Fonts:", -1,
                          width/2, 300, DSTF_CENTER);

     for (i=0; i<fontname_count; i++)
          surface->DrawString (surface, fontname_list[i], -1,
                               width/2, 340 + i * 20, DSTF_CENTER);

     fixedfont->Release (fixedfont);
}

static DFBEnumerationResult
encoding_callback( DFBTextEncodingID  id,
                   const char        *name,
                   void              *context )
{
     printf( "  (%02d) %s\n", id, name );

     return DFENUM_OK;
}

static void
render_font_page (IDirectFBSurface *surface,
                  const char       *fontname,
                  unsigned int      first_char)
{
     DFBFontDescription fontdesc;
     IDirectFBFont *font, *fixedfont;
     int width, height;
     int bwidth, bheight;
     int xborder, yborder;
     int baseoffset;
     int ascender, descender;
     char label[32];
     int i, j;

     surface->GetSize (surface, &width, &height);

     bwidth = width * 7 / 8;
     bheight = height * 7 / 8;

     xborder = (width - bwidth) / 2;
     yborder = (height - bheight) / 2;

     fontdesc.flags = DFDESC_ATTRIBUTES;
     fontdesc.attributes = antialias ? 0 : DFFA_MONOCHROME;

     DFBCHECK(dfb->CreateFont (dfb, NULL, &fontdesc, &fixedfont));
     surface->SetFont (surface, fixedfont);

     fontdesc.flags = DFDESC_HEIGHT | DFDESC_ATTRIBUTES;
     fontdesc.height = 9 * bheight / glyphs_per_yline / 16;
     fontdesc.attributes = antialias ? 0 : DFFA_MONOCHROME;
     fontdesc.attributes |= unicode_mode ? 0 : DFFA_NOCHARMAP;

     if (dfb->CreateFont (dfb, fontname, &fontdesc, &font) != DFB_OK) {

          static const char *msg = "failed opening '";
          char text [strlen(msg) + strlen(fontname) + 2];

          strcpy (text, msg);
          strcpy (text + strlen(msg), fontname);
          strcpy (text + strlen(msg) + strlen(fontname), "'");

          surface->SetColor (surface, 0xff, 0x00, 0x00, 0xff);
          surface->DrawString (surface,
                               text, -1, width/2, 10, DSTF_TOPCENTER);
          return;
     }

     {
          static bool done = false;

          if (!done) {
               printf( "\nEncodings\n" );
               font->EnumEncodings( font, encoding_callback, NULL );
               done = true;
          }
     }

     font->GetAscender (font, &ascender);
     font->GetDescender (font, &descender);

     baseoffset = ((bheight / glyphs_per_yline - (ascender - descender)) /
                   2 + ascender);

     surface->SetColor (surface, 0xa0, 0xa0, 0xa0, 0xff);

     surface->DrawString (surface,
                          fontname, -1, width/2, 10, DSTF_TOPCENTER);

     surface->DrawString (surface,
                          unicode_mode ? "Unicode Map" : "Raw Map", -1,
                          10, 10, DSTF_TOPLEFT);

     snprintf (label, sizeof(label), "%d pixels", fontdesc.height);
     surface->DrawString (surface,
                          label, -1, width-10, 10, DSTF_TOPRIGHT);

     surface->DrawString (surface, "Press F1 for Help", -1,
                          width/2, height-15, DSTF_CENTER);

     surface->SetColor (surface, 0xc0, 0xc0, 0xc0, 0xff);

     for (j=0; j<glyphs_per_yline; j++) {
          int basey;

          basey = j * bheight / glyphs_per_yline + yborder + baseoffset;

          snprintf (label, sizeof(label), "%04x",
                    first_char + j * glyphs_per_xline);

          surface->DrawString (surface, label, -1,
                               xborder-10, basey, DSTF_RIGHT);

          snprintf (label, sizeof(label), "%04x",
                    first_char + (j+1) * glyphs_per_yline - 1);

          surface->DrawString (surface, label, -1,
                               bwidth + xborder+10, basey, DSTF_LEFT);
     }

     fixedfont->Release (fixedfont);


     /*** FIXME: turn DrawLines into FillRectangles! ***/


     for (i=0; i<=glyphs_per_xline; i++)
          surface->DrawLine (surface,
                             i * bwidth / glyphs_per_xline + xborder,
                             yborder,
                             i * bwidth / glyphs_per_xline + xborder,
                             bheight + yborder);

     for (j=0; j<=glyphs_per_yline; j++)
          surface->DrawLine (surface,
                             xborder,
                             j * bheight / glyphs_per_yline + yborder,
                             bwidth + xborder,
                             j * bheight / glyphs_per_yline + yborder);

     if (show_ascender) {
          surface->SetColor (surface, 0xf0, 0x80, 0x80, 0xff);

          for (j=0; j<glyphs_per_yline; j++) {
               int basey;

               basey = j * bheight / glyphs_per_yline + yborder + baseoffset;
               surface->DrawLine (surface,
                                  xborder, basey - ascender,
                                  bwidth + xborder, basey - ascender);
          }
     }

     if (show_descender) {
          surface->SetColor (surface, 0x80, 0xf0, 0x80, 0xff);

          for (j=0; j<glyphs_per_yline; j++) {
               int basey;

               basey = j * bheight / glyphs_per_yline + yborder + baseoffset;
               surface->DrawLine (surface,
                                  xborder, basey - descender,
                                  bwidth + xborder, basey - descender);
          }
     }

     if (show_baseline) {
          surface->SetColor (surface, 0x80, 0x80, 0xf0, 0xff);

          for (j=0; j<glyphs_per_yline; j++) {
               int basey;

               basey = j * bheight / glyphs_per_yline + yborder + baseoffset;
               surface->DrawLine (surface,
                                  xborder, basey, bwidth + xborder, basey);
          }
     }

     surface->SetFont (surface, font);

     for (j=0; j<glyphs_per_yline; j++) {
          for (i=0; i<glyphs_per_xline; i++) {
               int basex;
               int basey;
               int glyphindex;
               int glyphadvance;
               DFBRectangle glyphrect;

               basex = (2*i+1) * bwidth / glyphs_per_xline /2 + xborder;
               basey = j * bheight / glyphs_per_yline + yborder + baseoffset;

               glyphindex = first_char + i+j*glyphs_per_xline;

               font->GetGlyphExtents (font,
                                      glyphindex, &glyphrect, &glyphadvance);

               if (show_glyphrect) {
                    int x = basex + glyphrect.x - glyphrect.w/2;
                    int y = basey + glyphrect.y;

                    surface->SetColor (surface, 0xc0, 0xc0, 0xf0, 0xff);
                    surface->FillRectangle (surface,
                                            x, y, glyphrect.w, glyphrect.h);
               }

               if (show_glyphadvance) {
                    int y = (j+1) * bheight / glyphs_per_yline + yborder - 4;

                    surface->SetColor (surface, 0x30, 0xc0, 0x30, 0xff);
                    surface->FillRectangle (surface,
                                            basex - glyphrect.w / 2, y,
                                            glyphadvance, 3);
               }

               surface->SetColor (surface, 0x00, 0x00, 0x00, 0xff);
               surface->DrawGlyph (surface, glyphindex,
                                   basex - glyphrect.w/2,
                                   basey, DSTF_LEFT);

               if (show_glyphorigin) {
                    surface->SetColor (surface, 0xff, 0x30, 0x30, 0xff);
                    surface->FillRectangle (surface,
                                            basex-1, basey-1, 2, 2);
               }
          }
     }

     font->Release (font);
}

static void
cleanup( void )
{
     if (keybuffer) keybuffer->Release (keybuffer);
     if (surface)   surface->Release (surface);
     if (layer)     layer->Release (layer);
     if (dfb)       dfb->Release (dfb);
}

static void
print_usage( void )
{
     printf ("DirectFB Font Viewer version " VERSION "\n\n");
     printf ("Usage: df_fonts <fontfile> ... <fontfile>\n\n");
}

int
main( int argc, char *argv[] )
{
     DFBSurfaceDescription surface_desc;
     DFBInputEvent evt;
     int first_glyph  = 0;
     int current_font = 0;
     int update       = 1;

     if (argc < 2 || strcmp(argv[1], "--help") == 0) {
          print_usage();
          return EXIT_FAILURE;
     }

     fontname_count = argc - 1;
     fontname_list  = argv + 1;

     DFBCHECK(DirectFBInit(&argc, &argv));
     DFBCHECK(DirectFBSetOption("bg-none", NULL));
     DFBCHECK(DirectFBCreate(&dfb));

     atexit (cleanup);

     dfb->SetCooperativeLevel(dfb, DFSCL_FULLSCREEN);

     surface_desc.flags = DSDESC_CAPS;
     surface_desc.caps = DSCAPS_PRIMARY | DSCAPS_DOUBLE;

     DFBCHECK(dfb->CreateSurface(dfb, &surface_desc, &surface));

     DFBCHECK(dfb->CreateInputEventBuffer(dfb, DICAPS_KEYS,
                                          DFB_FALSE, &keybuffer));

     while (1) {
          char *full_fontname = fontname_list[current_font];

          if (update) {
               surface->Clear (surface, 0xff, 0xff, 0xff, 0xff);

               if (show_help)
                    render_help_page (surface);
               else
                    render_font_page (surface, full_fontname, first_glyph);

               surface->Flip (surface, NULL, DSFLIP_WAITFORSYNC);

               update = 0;
          }

          keybuffer->WaitForEvent(keybuffer);

          while (keybuffer->GetEvent(keybuffer, DFB_EVENT(&evt)) == DFB_OK) {

               if (evt.type == DIET_KEYRELEASE) {

                    if (show_help) {
                         show_help = 0;
                         update = 1;
                    }
               }
               else if (evt.type == DIET_KEYPRESS) {

                    switch (DFB_LOWER_CASE (evt.key_symbol)) {
                         case DIKS_ESCAPE:
                         case DIKS_EXIT:
                         case 'q':
                              return EXIT_SUCCESS;

                         case DIKS_PAGE_DOWN:
                         case DIKS_CURSOR_RIGHT:
                              first_glyph += GLYPHS_PER_PAGE;
                              if (first_glyph > 0xffff)
                                   first_glyph = 0;
                              update = 1;
                              break;

                         case DIKS_PAGE_UP:
                         case DIKS_CURSOR_LEFT:
                              first_glyph -= GLYPHS_PER_PAGE;
                              if (first_glyph < 0x0000)
                                   first_glyph = 0x10000 - GLYPHS_PER_PAGE;
                              update = 1;
                              break;

                         case DIKS_SPACE:
                         case DIKS_CURSOR_UP:
                              if (++current_font >= fontname_count)
                                   current_font = 0;
                              update = 1;
                              break;

                         case DIKS_BACKSPACE:
                         case DIKS_CURSOR_DOWN:
                              if (--current_font < 0)
                                   current_font = fontname_count-1;
                              update = 1;
                              break;

                         case 'a':
                              show_ascender = !show_ascender;
                              update = 1;
                              break;

                         case 'd':
                              show_descender = !show_descender;
                              update = 1;
                              break;

                         case 'b':
                              show_baseline = !show_baseline;
                              update = 1;
                              break;

                         case 'r':
                              show_glyphrect = !show_glyphrect;
                              update = 1;
                              break;

                         case 'g':
                              show_glyphadvance = !show_glyphadvance;
                              update = 1;
                              break;

                         case 'o':
                              show_glyphorigin = !show_glyphorigin;
                              update = 1;
                              break;

                         case 'u':
                              unicode_mode = !unicode_mode;
                              update = 1;
                              break;

                         case 'm':
                         case DIKS_F10:
                              antialias = !antialias;
                              update = 1;
                              break;

                         case 'h':
                         case DIKS_F1:
                         case DIKS_HELP:
                              if (!show_help) {
                                   show_help = 1;
                                   update = 1;
                              }
                              break;

                         case DIKS_MINUS_SIGN:
                              if (glyphs_per_xline > 1)
                                   glyphs_per_xline--;
                              if (glyphs_per_yline > 1)
                                   glyphs_per_yline--;
                              update = 1;
                              break;

                         case DIKS_PLUS_SIGN:
                              glyphs_per_xline++;
                              glyphs_per_yline++;
                              update = 1;
                              break;

                         default:
                              ;
                    }
               }
          }
     }

     return EXIT_SUCCESS;
}
