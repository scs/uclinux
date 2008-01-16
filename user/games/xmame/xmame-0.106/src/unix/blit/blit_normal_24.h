/* 24 bpp packed pixel normal blitting routines */

INLINE void FUNC_NAME(blit_normal_line_1)(SRC_PIXEL *src,
  SRC_PIXEL *end, RENDER_PIXEL *dst, unsigned int *lookup)
{
   for(;src<end;dst+=3,src+=4)
   {
      *(dst  ) = (GETPIXEL(*(src  ))    ) | (GETPIXEL(*(src+1))<<24);
      *(dst+1) = (GETPIXEL(*(src+1))>> 8) | (GETPIXEL(*(src+2))<<16);
      *(dst+2) = (GETPIXEL(*(src+2))>>16) | (GETPIXEL(*(src+3))<< 8);
   }
}

INLINE void FUNC_NAME(blit_normal_line_2)(SRC_PIXEL *src,
  SRC_PIXEL *end, RENDER_PIXEL *dst, unsigned int *lookup)
{
   for(;src<end; src+=2, dst+=3)
   {
      *(dst  ) = (GETPIXEL(*(src  ))    ) | (GETPIXEL(*(src  ))<<24);
      *(dst+1) = (GETPIXEL(*(src  ))>> 8) | (GETPIXEL(*(src+1))<<16);
      *(dst+2) = (GETPIXEL(*(src+1))>>16) | (GETPIXEL(*(src+1))<<8);
   }
}

INLINE void FUNC_NAME(blit_normal_line_x)(SRC_PIXEL *src,
  SRC_PIXEL *end, RENDER_PIXEL *dst, unsigned int *lookup)
{
   RENDER_PIXEL pixel;
   int i, step=0;
   for(;src<end;src++)
   {
      pixel = GETPIXEL(*src);
      for(i=0; i<sysdep_display_params.widthscale; i++,step=(step+1)&3)
      {
         switch(step)
         {
            case 0:
               *(dst  )  = pixel;
               break;
            case 1:
               *(dst  ) |= pixel << 24;
               *(dst+1)  = pixel >> 8;
               break;
            case 2:
               *(dst+1) |= pixel << 16;
               *(dst+2)  = pixel >> 16;
               break;
            case 3:
               *(dst+2) |= pixel << 8;
               dst+=3;
               break;
         }
      }
   }
}

BLIT_BEGIN(blit_normal)
  switch(sysdep_display_params.widthscale)
  {
    case 1:
      BLIT_LOOP_YARBSIZE(blit_normal_line_1)
      break;
    case 2:
      BLIT_LOOP_YARBSIZE(blit_normal_line_2)
      break;
    default:
      BLIT_LOOP_YARBSIZE(blit_normal_line_x)
  }
BLIT_END

BLIT_BEGIN(blit_fakescan_h)
  switch(sysdep_display_params.widthscale)
  {
    case 1:
      BLIT_LOOP_FAKESCAN(blit_normal_line_1)
      break;
    case 2:
      BLIT_LOOP_FAKESCAN(blit_normal_line_2)
      break;
    default:
      BLIT_LOOP_FAKESCAN(blit_normal_line_x)
  }
BLIT_END
