#undef SRC_PIXEL
#undef GETPIXEL

#undef RMASK
#undef GMASK
#undef BMASK
#undef RMASK_INV_HALF
#undef GMASK_INV_HALF
#undef BMASK_INV_HALF
#undef SHADE_HALF
#undef SHADE_FOURTH
#undef RENDER_PIXEL
#undef RGB_TO_RENDER_PIXEL
#undef RGB32_TO_RENDER_PIXEL

#undef DEST_PIXEL
#undef DEST_PIXEL_SIZE
#undef DEST_WIDTH

#undef RENDER_WIDTH
#undef RENDER_DEST
#undef BLIT_LINE

#undef BLIT_BEGIN
#undef BLIT_END

#undef BLIT_LOOP
#undef BLIT_LOOP2X
#undef BLIT_LOOP2X_DFB
#undef BLIT_LOOP_YARBSIZE_NORMAL
#undef BLIT_LOOP_YARBSIZE_DFB
#undef BLIT_LOOP_YARBSIZE

/* this saves us from having to undef these each time in the files using
   the blit macros */
#undef FUNC_NAME
#undef SRC_DEPTH
#undef DEST_DEPTH
#undef RENDER_DEPTH
#ifdef BLIT_LINE_FUNC
#undef BLIT_LINE_FUNC
#endif
