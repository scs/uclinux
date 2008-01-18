/*
   (c) Copyright 2000-2002  convergence integrated media GmbH.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#include <pthread.h>

#include <directfb.h>

/* macro for a safe call to DirectFB functions */
#define DFBCHECK(x...) \
        {                                                                      \
           ret = x;                                                            \
           if (ret != DFB_OK) {                                                \
              fprintf( stderr, "%s <%d>:\n\t", __FILE__, __LINE__ );           \
              DirectFBErrorFatal( #x, ret );                                   \
           }                                                                   \
        }
        
static IDirectFB        *dfb      = NULL;
static IDirectFBSurface *primary  = NULL;
static IDirectFBFont    *font     = NULL;
static const char       *filename = NULL;

static int screen_width, screen_height;

static void
test_file()
{
     DFBResult                 ret;
     DFBDataBufferDescription  ddsc;
     DFBSurfaceDescription     sdsc;
     IDirectFBDataBuffer      *buffer;
     IDirectFBImageProvider   *image_provider;
     IDirectFBVideoProvider   *video_provider;

     primary->Clear( primary, 0, 0, 0, 0 );

     /* create a data buffer for a file */
     ddsc.flags = DBDESC_FILE;
     ddsc.file  = filename;

     DFBCHECK(dfb->CreateDataBuffer( dfb, &ddsc, &buffer ));

     ret = buffer->CreateImageProvider( buffer, &image_provider );
     if (ret == DFB_OK) {
          DFBCHECK(image_provider->GetSurfaceDescription( image_provider, &sdsc ));
          
          image_provider->Release( image_provider );
     }
     else {
          DirectFBError( "IDirectFBDataBuffer::CreateImageProvider()", ret );

          DFBCHECK(buffer->CreateVideoProvider( buffer, &video_provider ));
               
          DFBCHECK(video_provider->GetSurfaceDescription( video_provider, &sdsc ));
          
          video_provider->Release( video_provider );
     }

     printf( "\nImage size: %dx%d\n\n", sdsc.width, sdsc.height );
     
     buffer->Release( buffer );
}

static void
test_file_mmap()
{
     DFBResult                 ret;
     DFBDataBufferDescription  ddsc;
     DFBSurfaceDescription     sdsc;
     IDirectFBDataBuffer      *buffer;
     IDirectFBImageProvider   *image_provider;
     IDirectFBVideoProvider   *video_provider;

     int                       fd;
     void                     *data;
     struct stat               stat;

     primary->Clear( primary, 0, 0, 0, 0 );

     fd = open( filename, O_RDONLY );
     if (fd < 0) {
          perror( "open" );
          return;
     }

     if (fstat( fd, &stat ) < 0) {
          perror( "fstat" );
          close( fd );
          return;
     }

     data = mmap( NULL, stat.st_size, PROT_READ, MAP_SHARED, fd, 0 );
     if (data == MAP_FAILED) {
          perror( "mmap" );
          close( fd );
          return;
     }

     /* create a data buffer for memory */
     ddsc.flags         = DBDESC_MEMORY;
     ddsc.memory.data   = data;
     ddsc.memory.length = stat.st_size;

     DFBCHECK(dfb->CreateDataBuffer( dfb, &ddsc, &buffer ));

     ret = buffer->CreateImageProvider( buffer, &image_provider );
     if (ret == DFB_OK) {
          DFBCHECK(image_provider->GetSurfaceDescription( image_provider, &sdsc ));
          
          image_provider->Release( image_provider );
     }
     else {
          DirectFBError( "IDirectFBDataBuffer::CreateImageProvider()", ret );

          DFBCHECK(buffer->CreateVideoProvider( buffer, &video_provider ));
               
          DFBCHECK(video_provider->GetSurfaceDescription( video_provider, &sdsc ));
          
          video_provider->Release( video_provider );
     }

     printf( "\nImage size: %dx%d\n\n", sdsc.width, sdsc.height );
     
     buffer->Release( buffer );

     munmap( data, stat.st_size );
     close( fd );
}

static void *
streaming_thread( void *arg )
{
     DFBResult            ret;
     int                  fd;
     unsigned int         len   = 0;
     int                  total = 0;
     char                 data[8192];
     struct stat          stat;
     DFBRectangle         rect;
     IDirectFBSurface    *progress;
     IDirectFBDataBuffer *buffer = (IDirectFBDataBuffer *) arg;
     
     fd = open( filename, O_RDONLY );
     if (fd < 0) {
          perror( "open" );
          return NULL;
     }

     if (fstat( fd, &stat ) < 0) {
          perror( "fstat" );
          close( fd );
          return NULL;
     }

     rect.x = 0;
     rect.y = screen_height - 10;
     rect.w = screen_width;
     rect.h = 5;

     DFBCHECK(primary->GetSubSurface( primary, &rect, &progress ));

     progress->SetColor( progress, 0, 0, 0xff, 0xff );
     
     primary->DrawString( primary, "Thread running, streaming data...",
                          -1, 10, 40, DSTF_TOPLEFT );
     
     while (1) {
          char msg[32];

          pthread_testcancel();

          usleep( ((rand()%1000000) + 2000000) / (stat.st_size >> 10) );
         
          /* actually limit the amount of data in buffer to 64 Kb */
          DFBCHECK(buffer->GetLength( buffer, &len ));
          if (len >= 64*1024)
               continue;

          /* put some data with variing length */
          len = read( fd, data, (rand()%8192) + 1 );
          if (len <= 0) {
               /* End-of-File */
               DFBCHECK(buffer->Finish( buffer ));
               break;
          }
          
          DFBCHECK(buffer->PutData( buffer, data, len ));

          total += len;
          

          DFBCHECK(buffer->GetLength( buffer, &len ));

          snprintf( msg, 32, "Bytes in buffer: %d", len );
          
          primary->SetColor( primary, 0, 0, 0, 0 );
          primary->FillRectangle( primary, 40, 80, 200, 25 );

          primary->SetColor( primary, 0xdd, 0xdd, 0xdd, 0xff );
          primary->DrawString( primary, msg, -1, 40, 80, DSTF_TOPLEFT );
          
          progress->FillRectangle( progress, 0, 0,
                                   total * screen_width / stat.st_size, 5 );
     }

     progress->Release( progress );

     close( fd );

     return NULL;
}

static DIRenderCallbackResult
render_callback( DFBRectangle *rect, void *ctx )
{
     int               width;
     int               height;
     IDirectFBSurface *image = (IDirectFBSurface*) ctx;

     image->GetSize( image, &width, &height );

     primary->Blit( primary, image, rect,
                    (screen_width - width) / 2 + rect->x,
                    (screen_height - height) / 2 + rect->y);

     return DIRCR_OK;
}

static void
frame_callback( void *ctx )
{
     int               width;
     int               height;
     IDirectFBSurface *image = (IDirectFBSurface*) ctx;

     image->GetSize( image, &width, &height );
     
     primary->Blit( primary, image, NULL, 
                    (screen_width - width) / 2,
                    (screen_height - height) / 2);
}

static void
test_file_streamed()
{
     DFBResult                 ret;
     DFBSurfaceDescription     sdsc;
     IDirectFBDataBuffer      *buffer;
     IDirectFBImageProvider   *image_provider = NULL;
     IDirectFBVideoProvider   *video_provider = NULL;
     IDirectFBSurface         *image;
     pthread_t                 st;
     
     if (access( filename, R_OK ) < 0) {
          perror( "access" );
          return;
     }          
     
     primary->Clear( primary, 0, 0, 0, 0 );
     primary->SetColor( primary, 0xcc, 0xcc, 0xcc, 0xff );

     /* create a streamed data buffer */
     DFBCHECK(dfb->CreateDataBuffer( dfb, NULL, &buffer ));

     primary->DrawString( primary, "Databuffer created, starting thread...",
                          -1, 10, 10, DSTF_TOPLEFT );
     
     /* create thread that will feed the buffer */
     pthread_create( &st, NULL, streaming_thread, buffer );
     
     ret = buffer->CreateImageProvider( buffer, &image_provider );
     if (ret == DFB_OK) {
          DFBCHECK(image_provider->GetSurfaceDescription( image_provider, &sdsc ));
     }
     else {
          DirectFBError( "IDirectFBDataBuffer::CreateImageProvider()", ret );

          DFBCHECK(buffer->CreateVideoProvider( buffer, &video_provider ));
               
          DFBCHECK(video_provider->GetSurfaceDescription( video_provider, &sdsc ));
     }

     printf( "\nImage size: %dx%d\n\n", sdsc.width, sdsc.height );

     DFBCHECK(dfb->CreateSurface( dfb, &sdsc, &image ));

     if (image_provider) {
          image_provider->SetRenderCallback( image_provider, render_callback, image );
     
          DFBCHECK(image_provider->RenderTo( image_provider, image, NULL ));
     } /* video_provider */
     else { 
          DFBCHECK(video_provider->PlayTo( video_provider, image, NULL,
                                                  frame_callback, image ));

          /* play 10 seconds */
          sleep( 10 );

          video_provider->Stop( video_provider );
     }

     pthread_cancel( st );
     pthread_join( st, NULL );
     
     primary->Blit( primary, image, NULL,
                    (screen_width - (int)sdsc.width) / 2,
                    (screen_height - (int)sdsc.height) / 2);
     
     image->Release( image );
     if (image_provider)
          image_provider->Release( image_provider );
     if (video_provider)
          video_provider->Release( video_provider );
     buffer->Release( buffer );
     
     sleep( 2 );
}

static void
init_resources( int *argc, char **argv[] )
{
     DFBResult             ret;
     DFBFontDescription    fdsc;
     DFBSurfaceDescription sdsc;

     /* init directfb command line parsing */
     DFBCHECK(DirectFBInit( argc, argv ));

     /* check arguments */
     if (*argc < 2) {
          fprintf( stderr, "\nUsage: df_databuffer <filename>\n\n" );
          exit(1);
     }

     /* use this file */
     filename = (*argv)[1];

     /* create the super interface */
     DFBCHECK(DirectFBCreate( &dfb ));

     /* switch to fullscreen */
     dfb->SetCooperativeLevel( dfb, DFSCL_FULLSCREEN );

     /* create the primary surface */
     sdsc.flags = DSDESC_CAPS;
     sdsc.caps  = DSCAPS_PRIMARY;

     DFBCHECK(dfb->CreateSurface( dfb, &sdsc, &primary ));

     primary->GetSize( primary, &screen_width, &screen_height );
     
     /* load a font */
     fdsc.flags  = DFDESC_HEIGHT;
     fdsc.height = 20;

     DFBCHECK(dfb->CreateFont( dfb, FONT, &fdsc, &font ));

     /* use the font */
     DFBCHECK(primary->SetFont( primary, font ));
}

static void
deinit_resources()
{
     /* release our interfaces to shutdown DirectFB */
     font->Release( font );
     primary->Release( primary );
     dfb->Release( dfb );
}

int main( int argc, char *argv[] )
{
     init_resources( &argc, &argv );

     test_file();
     test_file_mmap();
     test_file_streamed();

     deinit_resources();

     return 0;
}

