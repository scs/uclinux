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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <directfb.h>
#include <directfb_keynames.h>

#define CLAMP(x, low, high)\
             (((x) > (high)) ? (high) : (((x) < (low)) ? (low) : (x)))


/* the super interface */
static IDirectFB            *dfb;

/* the primary surface (surface of primary layer) */
static IDirectFBSurface     *primary;

/* fonts */
static IDirectFBFont        *font_small;
static IDirectFBFont        *font_normal;
static IDirectFBFont        *font_large;

/* images */
static IDirectFBSurface     *keys_image     = NULL;
static IDirectFBSurface     *mouse_image    = NULL;
static IDirectFBSurface     *joystick_image = NULL;

/* input interfaces: device and its buffer */
static IDirectFBEventBuffer *events;

static int screen_width, screen_height;
static int mouse_x, mouse_y;
static int joy_axis[8];


static const DirectFBKeySymbolNames(keynames);
static const DirectFBKeyIdentifierNames(idnames);

/* macro for a safe call to DirectFB functions */
#define DFBCHECK(x...) \
     {                                                               \
           err = x;                                                  \
           if (err != DFB_OK) {                                      \
              fprintf( stderr, "%s <%d>:\n\t", __FILE__, __LINE__ ); \
              DirectFBErrorFatal( #x, err );                         \
           }                                                         \
     }

static int
compare_symbol( const void *a, const void *b ) {
     DFBInputDeviceKeySymbol *symbol  = (DFBInputDeviceKeySymbol *) a;
     struct DFBKeySymbolName *symname = (struct DFBKeySymbolName *) b;

     return *symbol - symname->symbol;
}

static int
compare_id( const void *a, const void *b ) {
     DFBInputDeviceKeyIdentifier *id     = (DFBInputDeviceKeyIdentifier *) a;
     struct DFBKeyIdentifierName *idname = (struct DFBKeyIdentifierName *) b;

     return *id - idname->identifier;
}

static void
show_key_modifier_state( DFBInputEvent *evt )
{
     static struct {
          DFBInputDeviceModifierMask  modifier;
          const char                 *name;
          int                         x;
     } modifiers[] = {
          { DIMM_SHIFT,   "Shift", 0 },
          { DIMM_CONTROL, "Ctrl",  0 },
          { DIMM_ALT,     "Alt",   0 },
          { DIMM_ALTGR,   "AltGr", 0 },
          { DIMM_META,    "Meta",  0 },
          { DIMM_SUPER,   "Super", 0 },
          { DIMM_HYPER,   "Hyper", 0 }
     };
     static int n_modifiers = sizeof(modifiers) / sizeof(modifiers[0]);
     static int y           = 0;

     int i;

     if (!(evt->flags & DIEF_MODIFIERS))
          return;

     if (!y) {
          y = 2 * screen_height / 3 + 20;

          modifiers[0].x = 40;
          for (i = 0; i < n_modifiers - 1; i++) {
               int w;

               font_normal->GetStringWidth (font_normal,
                                            modifiers[i].name, -1, &w);
               modifiers[i+1].x = modifiers[i].x + w + 20;
          }
     }

     primary->SetFont( primary, font_normal );

     for (i = 0; i < n_modifiers; i++) {
          if (evt->modifiers & modifiers[i].modifier)
               primary->SetColor( primary, 0x90, 0x30, 0x90, 0xFF );
          else
               primary->SetColor( primary, 0x20, 0x20, 0x20, 0xFF );

          primary->DrawString( primary, modifiers[i].name, -1,
                               modifiers[i].x, y, DSTF_TOPLEFT );
     }
}

static void
show_key_lock_state( DFBInputEvent *evt )
{
     static struct {
          DFBInputDeviceLockState  lock;
          const char              *name;
          int                      x;
     } locks[] = {
          { DILS_SCROLL, "ScrollLock", 0 },
          { DILS_NUM,    "NumLock",    0 },
          { DILS_CAPS,   "CapsLock",   0 },
     };
     static int n_locks = sizeof(locks) / sizeof(locks[0]);
     static int y       = 0;

     int i;

     if (!(evt->flags & DIEF_LOCKS))
          return;

     if (!y) {
          int w;

          y = screen_height - 40;

          font_normal->GetStringWidth (font_normal,
                                       locks[n_locks-1].name, -1, &w);
          locks[n_locks-1].x = screen_width - 40 - w;

          for (i = n_locks - 1; i > 0; i--) {
               int w;

               font_normal->GetStringWidth (font_normal,
                                            locks[i-1].name, -1, &w);
               locks[i-1].x = locks[i].x - w - 20;
          }
     }

     primary->SetFont( primary, font_normal );

     for (i = 0; i < n_locks; i++) {
          if (evt->locks & locks[i].lock)
               primary->SetColor( primary, 0x90, 0x30, 0x90, 0xFF );
          else
               primary->SetColor( primary, 0x20, 0x20, 0x20, 0xFF );

          primary->DrawString( primary, locks[i].name, -1,
                               locks[i].x, y, DSTF_LEFT );
     }
}

static void
show_key_event( DFBInputEvent *evt )
{
     static DFBInputDeviceKeyIdentifier last_id = DIKI_UNKNOWN;
     static int                         count   = 0;

     char                         buf[16];
     struct DFBKeySymbolName     *symbol_name;
     struct DFBKeyIdentifierName *id_name;

     if (DFB_KEY_TYPE( evt->key_symbol ) == DIKT_UNICODE) {
          primary->SetFont( primary, font_large );
          primary->SetColor( primary, 0x70, 0x80, 0xE0, 0xFF );
          primary->DrawGlyph( primary, evt->key_symbol,
                              screen_width/2, screen_height/2,
                              DSTF_CENTER );
     }

     symbol_name = bsearch( &evt->key_symbol, keynames,
                            sizeof(keynames) / sizeof(keynames[0]) - 1,
                            sizeof(keynames[0]), compare_symbol );


     primary->SetFont( primary, font_normal );

     if (symbol_name) {
          primary->SetColor( primary, 0xF0, 0xC0, 0x30, 0xFF );
          primary->DrawString( primary, symbol_name->name, -1,
                               40, screen_height/3, DSTF_LEFT );
     }

     primary->SetColor( primary, 0x60, 0x60, 0x60, 0xFF );
     snprintf (buf, sizeof(buf), "0x%X", evt->key_symbol);
     primary->DrawString( primary, buf, -1,
                          screen_width - 40, screen_height/3,
                          DSTF_RIGHT );

     primary->SetFont( primary, font_small );

     primary->SetColor( primary, 0x80, 0x80, 0x80, 0xFF );
     snprintf (buf, sizeof(buf), "%d", evt->key_code);
     primary->DrawString( primary, buf, -1,
                          screen_width - 40, screen_height/4,
                          DSTF_RIGHT );

     primary->SetFont( primary, font_normal );

     id_name = bsearch( &evt->key_id, idnames,
                        sizeof(idnames) / sizeof(idnames[0]) - 1,
                        sizeof(idnames[0]), compare_id );

     if (id_name) {
          primary->SetColor( primary, 0x60, 0x60, 0x60, 0xFF );
          primary->DrawString( primary, id_name->name, -1,
                               40, 2 * screen_height/3, DSTF_LEFT );
     }

     show_key_modifier_state( evt );
     show_key_lock_state( evt );

     if (evt->type == DIET_KEYPRESS) {
          if (evt->key_id != DIKI_UNKNOWN && evt->key_id == last_id)
               count++;
          else
               count = 0;
          last_id = evt->key_id;
     } else {
          count = 0;
          last_id = DIKI_UNKNOWN;
     }


     primary->SetColor( primary, 0x60, 0x60, 0x60, 0xFF );

     if (count > 0) {
          snprintf (buf, sizeof(buf), "%dx PRESS", count + 1);

          primary->DrawString( primary, buf, -1,
                               screen_width - 40, 2 * screen_height/3,
                               DSTF_RIGHT );
     }
     else
          primary->DrawString( primary, (evt->type == DIET_KEYPRESS) ?
                               "PRESS" : "RELEASE", -1,
                               screen_width - 40, 2 * screen_height/3,
                               DSTF_RIGHT );


     if (evt->key_symbol == DIKS_ESCAPE || evt->key_symbol == DIKS_EXIT) {
          primary->SetFont( primary, font_small );
          primary->SetColor( primary, 0xF0, 0xC0, 0x30, 0xFF );
          primary->DrawString( primary, "Press ESC/EXIT again to quit", -1,
                               screen_width/2, screen_height/6,
                               DSTF_CENTER );
     }
}

static void
show_mouse_buttons (DFBInputEvent *evt)
{
     static struct {
          DFBInputDeviceButtonMask  mask;
          const char               *name;
          int                       x;
     } buttons[] = {
          { DIBM_LEFT,   "Left",   0 },
          { DIBM_MIDDLE, "Middle", 0 },
          { DIBM_RIGHT,  "Right",  0 },
     };
     static int n_buttons = sizeof(buttons) / sizeof(buttons[0]);
     static int y         = 0;

     int i;

     if (!y) {
          int w;

          y = screen_height - 40;

          font_normal->GetStringWidth (font_normal,
                                       buttons[n_buttons-1].name, -1, &w);
          buttons[n_buttons-1].x = screen_width - 40 - w;

          for (i = n_buttons-1; i > 0; i--) {
               font_normal->GetStringWidth (font_normal,
                                            buttons[i-1].name, -1, &w);
               buttons[i-1].x = buttons[i].x - w - 20;
          }
     }

     for (i = 0; i < n_buttons; i++) {
          if (evt->flags & DIEF_BUTTONS && evt->buttons & buttons[i].mask)
               primary->SetColor( primary, 0x90, 0x30, 0x90, 0xFF );
          else
               primary->SetColor( primary, 0x20, 0x20, 0x20, 0xFF );

          primary->DrawString( primary, buttons[i].name, -1,
                               buttons[i].x, y, DSTF_LEFT );
     }
}

static void
show_mouse_event( DFBInputEvent *evt )
{
     char buf[32];

     primary->SetFont( primary, font_normal );

     show_mouse_buttons( evt );

     *buf = 0;

     if (evt->type == DIET_AXISMOTION) {
          if (evt->flags & DIEF_AXISABS) {
               switch (evt->axis) {
               case DIAI_X:
                    mouse_x = evt->axisabs;
               break;
               case DIAI_Y:
                    mouse_y = evt->axisabs;
                    break;
               case DIAI_Z:
                    snprintf (buf, sizeof(buf),
                              "Z axis (abs): %d", evt->axisabs);
	            break;
               default:
                    snprintf (buf, sizeof(buf),
                              "Axis %d (abs): %d", evt->axis, evt->axisabs);
                    break;
               }
          }
          else if (evt->flags & DIEF_AXISREL) {
               switch (evt->axis) {
               case DIAI_X:
 	            mouse_x += evt->axisrel;
                    break;
               case DIAI_Y:
                    mouse_y += evt->axisrel;
                    break;
               case DIAI_Z:
                    snprintf (buf, sizeof(buf),
                              "Z axis (rel): %d", evt->axisrel);
	            break;
               default:
                    snprintf (buf, sizeof(buf),
                              "Axis %d (rel): %d", evt->axis, evt->axisrel);
                    break;
               }
          }

          mouse_x = CLAMP (mouse_x, 0, screen_width  - 1);
          mouse_y = CLAMP (mouse_y, 0, screen_height - 1);
     }
     else {  /* BUTTON_PRESS or BUTTON_RELEASE */
          snprintf (buf, sizeof(buf), "Button %d", evt->button);
     }

     if (*buf) {
          primary->SetColor( primary, 0xF0, 0xC0, 0x30, 0xFF );
          primary->DrawString( primary, buf, -1,
                               40, screen_height - 40, DSTF_LEFT );
     }

     primary->SetColor( primary, 0x70, 0x80, 0xE0, 0xFF );
     primary->FillRectangle( primary, mouse_x, 0, 1, screen_height );
     primary->FillRectangle( primary, 0, mouse_y, screen_width, 1 );
}

static void
show_any_button_event( DFBInputEvent *evt )
{
     char buf[40];

     primary->SetFont( primary, font_normal );

     snprintf (buf, sizeof(buf), "Button %d %s", evt->button,
               (evt->type == DIET_BUTTONPRESS) ? "pressed" : "released");

     primary->SetColor( primary, 0xF0, 0xC0, 0x30, 0xFF );
     primary->DrawString( primary, buf, -1,
                          40, screen_height - 40, DSTF_LEFT );
}

static void
show_any_axis_event( DFBInputEvent *evt )
{
     char buf[32];

     primary->SetFont( primary, font_normal );

     if (evt->flags & DIEF_AXISABS)
          snprintf (buf, sizeof(buf),
                    "Axis %d (abs): %d", evt->axis, evt->axisabs);
     else
          snprintf (buf, sizeof(buf),
                    "Axis %d (rel): %d", evt->axis, evt->axisrel);

     primary->SetColor( primary, 0xF0, 0xC0, 0x30, 0xFF );
     primary->DrawString( primary, buf, -1,
                          40, screen_height - 40, DSTF_LEFT );
}

static inline int
joystick_calc_screenlocation( int screenres, int axisvalue )
{
     return ((axisvalue + 32768)/65535.0f) * (screenres - 1);
}

static void
joystick_show_axisgroup( DFBRectangle *rect, int axis_x, int axis_y )
{
     int screen_x;
     int screen_y;

     screen_x = joystick_calc_screenlocation( rect->w, axis_x );
     screen_y = joystick_calc_screenlocation( rect->h, axis_y );
     
     primary->SetColor( primary, 0x80, 0x80, 0x80, 0xFF );
     primary->DrawRectangle( primary, rect->x, rect->y, rect->w, rect->h );
     
     primary->SetColor( primary, 0x00, 0x00, 0xFF, 0xFF );
     primary->DrawLine( primary, screen_x+rect->x, rect->y,
                                 screen_x+rect->x, rect->y + rect->h-1 );
     primary->DrawLine( primary, rect->x, screen_y + rect->y,
                                 rect->x + rect->w-1, screen_y + rect->y );          
}

static void
show_joystick_event( DFBInputEvent *evt )
{
     char buf[32];
     
     DFBRectangle rect;

     primary->SetFont( primary, font_normal );

     *buf = 0;

     if ((evt->type == DIET_AXISMOTION) && (evt->axis < 8)) {
          if (evt->flags & DIEF_AXISABS)
               joy_axis[evt->axis] = evt->axisabs;
          else if (evt->flags & DIEF_AXISREL)
               joy_axis[evt->axis] += evt->axisrel;
     }
     else {  /* BUTTON_PRESS or BUTTON_RELEASE */
          snprintf (buf, sizeof(buf), "Button %d", evt->button);
     }

     if (*buf) {
          primary->SetColor( primary, 0xF0, 0xC0, 0x30, 0xFF );
          primary->DrawString( primary, buf, -1,
                               40, screen_height - 40, DSTF_LEFT );
     }
     
     rect.x = 0;
     rect.y = 0;
     rect.w = screen_width/2 - 10;
     rect.h = screen_height/2 - 10;
     joystick_show_axisgroup( &rect, joy_axis[0], joy_axis[1]);

     rect.x+= screen_width/2;
     joystick_show_axisgroup( &rect, joy_axis[2], joy_axis[3]);

     rect.y+= screen_height/2;
     joystick_show_axisgroup( &rect, joy_axis[4], joy_axis[5]); 
}

static void
show_event( const char              *device_name,
            DFBInputDeviceTypeFlags  device_type,
            DFBInputEvent           *evt )
{
     char buf[128];

     primary->SetFont( primary, font_small );

     snprintf (buf, sizeof(buf), "%s (Device ID %d)",
               device_name, evt->device_id);
     primary->SetColor( primary, 0x60, 0x60, 0x60, 0xFF );
     primary->DrawString( primary, buf, -1,
                          100, 40, DSTF_TOP );

     switch (evt->type) {
          case DIET_KEYPRESS:
          case DIET_KEYRELEASE:
               primary->Blit( primary, keys_image, NULL, 40, 40 );
               show_key_event( evt );
               break;

          case DIET_BUTTONPRESS:
          case DIET_BUTTONRELEASE:
          case DIET_AXISMOTION:
               if (device_type & DIDTF_MOUSE ) {
                    primary->Blit( primary, mouse_image, NULL, 40, 40 );
                    show_mouse_event( evt );
               }
               else if (device_type & DIDTF_JOYSTICK) {
                    primary->Blit( primary, joystick_image, NULL, 40, 40 );
                    show_joystick_event( evt );
               }
               else {
                    if (evt->type == DIET_BUTTONPRESS || evt->type == DIET_BUTTONRELEASE)
                         show_any_button_event( evt );
                    else
                         show_any_axis_event( evt );
               }
               break;

          default:
               break;
     }
}

static IDirectFBSurface *
load_image (const char *filename)
{
     IDirectFBImageProvider *provider;
     IDirectFBSurface       *tmp     = NULL;
     IDirectFBSurface       *surface = NULL;
     DFBSurfaceDescription   dsc;
     DFBResult               err;

     err = dfb->CreateImageProvider( dfb, filename, &provider );
     if (err != DFB_OK) {
          fprintf( stderr, "Couldn't load image from file '%s': %s\n",
                   filename, DirectFBErrorString( err ));
          return NULL;
     }

     provider->GetSurfaceDescription( provider, &dsc );
     dsc.flags = DSDESC_WIDTH | DSDESC_HEIGHT | DSDESC_PIXELFORMAT;
     dsc.pixelformat = DSPF_ARGB;
     if (dfb->CreateSurface( dfb, &dsc, &tmp ) == DFB_OK)
          provider->RenderTo( provider, tmp, NULL );

     provider->Release( provider );

     if (tmp) {
          primary->GetPixelFormat( primary, &dsc.pixelformat );
          if (dfb->CreateSurface( dfb, &dsc, &surface ) == DFB_OK) {
               surface->Clear( surface, 0, 0, 0, 0xFF );
               surface->SetBlittingFlags( surface, DSBLIT_BLEND_ALPHACHANNEL );
               surface->Blit( surface, tmp, NULL, 0, 0 );
          }
          tmp->Release( tmp );
     }

     return surface;
}

typedef struct _DeviceInfo DeviceInfo;

struct _DeviceInfo {
     DFBInputDeviceID           device_id;
     DFBInputDeviceDescription  desc;
     DeviceInfo                *next;
};

static DFBEnumerationResult
enum_input_device( DFBInputDeviceID           device_id,
                   DFBInputDeviceDescription  desc,
                   void                      *data )
{
     DeviceInfo **devices = data;
     DeviceInfo  *device;

     device = malloc( sizeof(DeviceInfo) );

     device->device_id = device_id;
     device->desc      = desc;
     device->next      = *devices;

     *devices = device;

     return DFENUM_OK;
}

const char *
get_device_name( DeviceInfo       *devices,
                 DFBInputDeviceID  device_id )
{
     while (devices) {
          if (devices->device_id == device_id)
               return devices->desc.name;
          devices = devices->next;
     }

     return "<unknown>";
}

DFBInputDeviceTypeFlags
get_device_type( DeviceInfo       *devices,
                 DFBInputDeviceID  device_id )
{
     while (devices) {
          if (devices->device_id == device_id)
               return devices->desc.type;
          devices = devices->next;
     }

     return DIDTF_NONE;
}

static void
print_usage( void )
{
     printf ("DirectFB Input Demo version " VERSION "\n\n");
     printf ("Usage: df_input [options]\n\n");
     printf ("Options:\n\n");
     printf ("  --font <filename>            Use the specified font file.\n");
     printf ("  --help                       Print usage information.\n");
     printf ("  --dfb-help                   Output DirectFB usage information.\n\n");
}

int
main( int argc, char *argv[] )
{
     DFBResult              err;
     DFBSurfaceDescription  sdsc;
     DFBFontDescription     fdsc;
     const char            *fontfile = FONT;
     int                    n;
     DeviceInfo            *devices = NULL;

     DFBCHECK(DirectFBInit( &argc, &argv ));

     /* parse command line */
     for (n = 1; n < argc; n++) {
          if (strncmp (argv[n], "--", 2) == 0) {
               if (strcmp (argv[n]+2, "help") == 0) {
                    print_usage();
                    return EXIT_SUCCESS;
               }
               else
               if (strcmp (argv[n]+2, "font") == 0 && ++n < argc && argv[n]) {
                    fontfile = argv[n];
                    continue;
               }
          }
          print_usage();
          return EXIT_FAILURE;
     }

     DirectFBSetOption ("bg-none", NULL);

     /* create the super interface */
     DFBCHECK(DirectFBCreate( &dfb ));

     /* create a list of input devices */
     dfb->EnumInputDevices( dfb, enum_input_device, &devices );

     /* create an event buffer for all devices */
     DFBCHECK(dfb->CreateInputEventBuffer( dfb, DICAPS_ALL,
                                           DFB_FALSE, &events ));

     /* set our cooperative level to DFSCL_FULLSCREEN
        for exclusive access to the primary layer */
     dfb->SetCooperativeLevel( dfb, DFSCL_FULLSCREEN );

     /* get the primary surface, i.e. the surface of the
        primary layer we have exclusive access to */
     sdsc.flags = DSDESC_CAPS;
     sdsc.caps  = DSCAPS_PRIMARY | DSCAPS_DOUBLE;

     DFBCHECK(dfb->CreateSurface( dfb, &sdsc, &primary ));

     primary->GetSize( primary, &screen_width, &screen_height );

     mouse_x = screen_width  / 2;
     mouse_y = screen_height / 2;

     fdsc.flags = DFDESC_HEIGHT;

     fdsc.height = screen_width / 30;
     DFBCHECK(dfb->CreateFont( dfb, fontfile, &fdsc, &font_small ));

     fdsc.height = screen_width / 20;
     DFBCHECK(dfb->CreateFont( dfb, fontfile, &fdsc, &font_normal ));

     fdsc.height = screen_width / 10;
     DFBCHECK(dfb->CreateFont( dfb, fontfile, &fdsc, &font_large ));

     primary->Clear( primary, 0, 0, 0, 0 );
     primary->SetFont( primary, font_normal );
     primary->SetColor( primary, 0x60, 0x60, 0x60, 0xFF );
     primary->DrawString( primary, "Press any key to continue.", -1,
                          screen_width/2, screen_height/2, DSTF_CENTER );
     primary->Flip( primary, NULL, 0 );

     keys_image  = load_image( DATADIR "/gnu-keys.png" );
     mouse_image = load_image( DATADIR "/gnome-mouse.png" );
     joystick_image = load_image (DATADIR "/joystick.png" );

     if (events->WaitForEventWithTimeout( events, 10, 0 ) == DFB_TIMEOUT) {
          primary->Clear( primary, 0, 0, 0, 0 );
          primary->DrawString( primary, "Timed out.", -1,
                               screen_width/2, screen_height/2, DSTF_CENTER );
          primary->Flip( primary, NULL, 0 );
          primary->Clear( primary, 0, 0, 0, 0 );
          sleep( 1 );
     }
     else {
          DFBInputDeviceKeySymbol  last_symbol = DIKS_NULL;

          while (1) {
               DFBInputEvent evt;

               while (events->GetEvent( events, DFB_EVENT(&evt) ) == DFB_OK) {
                    const char *device_name;
                    DFBInputDeviceTypeFlags device_type;

                    primary->Clear( primary, 0, 0, 0, 0 );

                    device_name  = get_device_name( devices, evt.device_id );
                    device_type  = get_device_type( devices, evt.device_id );
                     
                    show_event( device_name, device_type, &evt );
	
                    primary->Flip( primary, NULL, 0 );
               }

               if (evt.type == DIET_KEYRELEASE) {
                    if ((last_symbol == DIKS_ESCAPE || last_symbol == DIKS_EXIT) &&
                        (evt.key_symbol == DIKS_ESCAPE || evt.key_symbol == DIKS_EXIT))
                         break;
                    last_symbol = evt.key_symbol;
               }

               events->WaitForEvent( events );
          }
     }

     while (devices) {
          DeviceInfo *next = devices->next;

          free( devices );
          devices = next;
     }

     /* release our interfaces to shutdown DirectFB */
     if (keys_image)
          keys_image->Release( keys_image );
     if (mouse_image)
          mouse_image->Release( mouse_image );

     font_small->Release( font_small );
     font_normal->Release( font_normal );
     font_large->Release( font_large );

     primary->Release( primary );
     events->Release( events );
     dfb->Release( dfb );

     return 0;
}
