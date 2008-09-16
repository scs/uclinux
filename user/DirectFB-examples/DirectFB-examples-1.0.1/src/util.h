/*
   (c) Copyright 2000-2002  convergence integrated media GmbH.
   (c) Copyright 2002-2004  convergence GmbH.

   All rights reserved.

   Written by Denis Oliver Kropp <dok@directfb.org>,
              Andreas Hundt <andi@fischlustig.de>,
              Sven Neumann <neo@directfb.org> and
              Ville Syrjälä <syrjala@sci.fi>.

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

#ifndef __DFB_EXAMPLES__UTIL_H__
#define __DFB_EXAMPLES__UTIL_H__

#include <directfb.h>

#include <string.h>

#include <direct/clock.h>
#include <direct/debug.h>


typedef struct {
     int       magic;

     int       frames;
     float     fps;
     long long fps_time;
     char      fps_string[20];
} FPSData;

static inline void
fps_init( FPSData *data )
{
     D_ASSERT( data != NULL );

     memset( data, 0, sizeof(FPSData) );

     data->fps_time = direct_clock_get_millis();

     D_MAGIC_SET( data, FPSData );
}

static inline void
fps_count( FPSData *data,
           int      interval )
{
     long long diff;
     long long now = direct_clock_get_millis();

     D_MAGIC_ASSERT( data, FPSData );

     data->frames++;

     diff = now - data->fps_time;
     if (diff >= interval) {
          data->fps = data->frames * 1000 / (float) diff;

          snprintf( data->fps_string, sizeof(data->fps_string), "%.1f", data->fps );

          data->fps_time = now;
          data->frames   = 0;
     }
}


DFBResult
util_load_image (IDirectFB              *dfb,
                 const char             *filename,
                 DFBSurfacePixelFormat   pixelformat,
                 IDirectFBSurface      **surface,
                 unsigned int           *width,
                 unsigned int           *height,
                 DFBImageDescription    *desc)
{
     DFBResult               ret;
     DFBSurfaceDescription   dsc;
     IDirectFBSurface       *image;
     IDirectFBImageProvider *provider;

     if (!surface)
          return DFB_INVARG;

     /* Create an image provider for loading the file */
     ret = dfb->CreateImageProvider (dfb, filename, &provider);
     if (ret) {
          fprintf (stderr,
                   "load_image: CreateImageProvider for '%s': %s\n",
                   filename, DirectFBErrorString (ret));
          return ret;
     }

     /* Retrieve a surface description for the image */
     ret = provider->GetSurfaceDescription (provider, &dsc);
     if (ret) {
          fprintf (stderr,
                   "load_image: GetSurfaceDescription for '%s': %s\n",
                   filename, DirectFBErrorString (ret));
          provider->Release (provider);
          return ret;
     }

     /* Use the specified pixelformat if the image's pixelformat is not ARGB */
     if (pixelformat != DSPF_UNKNOWN && dsc.pixelformat != DSPF_ARGB)
          dsc.pixelformat = pixelformat;

     /* Create a surface using the description */
     ret = dfb->CreateSurface (dfb, &dsc, &image);
     if (ret) {
          fprintf (stderr,
                   "load_image: CreateSurface %dx%d: %s\n",
                   dsc.width, dsc.height, DirectFBErrorString (ret));
          provider->Release (provider);
          return ret;
     }

     /* Render the image to the created surface */
     ret = provider->RenderTo (provider, image, NULL);
     if (ret) {
          fprintf (stderr,
                   "load_image: RenderTo for '%s': %s\n",
                   filename, DirectFBErrorString (ret));
          image->Release (image);
          provider->Release (provider);
          return ret;
     }

     /* Return surface */
     *surface = image;

     /* Return width? */
     if (width)
          *width = dsc.width;

     /* Return height? */
     if (height)
          *height  = dsc.height;

     /* Retrieve the image description? */
     if (desc)
          provider->GetImageDescription (provider, desc);

     /* Release the provider */
     provider->Release (provider);

     return DFB_OK;
}

#endif

