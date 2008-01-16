#ifndef __BLIT_H
#define __BLIT_H

#include "sysdep/sysdep_display_priv.h"

void blit_normal_15_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_normal_16_16(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_normal_16_24(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_normal_16_32(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_normal_16_YUY2(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_normal_32_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_normal_32_16_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_normal_32_24_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_normal_32_32_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_normal_32_YUY2_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

/****************************************************************************/

void blit_scale2x_15_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scale2x_16_16(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scale2x_16_24(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scale2x_16_32(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scale2x_16_YUY2(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scale2x_32_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scale2x_32_16_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scale2x_32_24_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scale2x_32_32_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scale2x_32_YUY2_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

/****************************************************************************/

void blit_lq2x_15_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_lq2x_16_16(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_lq2x_16_24(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_lq2x_16_32(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_lq2x_16_YUY2(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_lq2x_32_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_lq2x_32_16_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_lq2x_32_24_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_lq2x_32_32_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_lq2x_32_YUY2_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

/****************************************************************************/

void blit_hq2x_15_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_hq2x_16_16(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_hq2x_16_24(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_hq2x_16_32(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_hq2x_16_YUY2(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_hq2x_32_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_hq2x_32_16_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_hq2x_32_24_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_hq2x_32_32_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_hq2x_32_YUY2_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

/****************************************************************************/

void blit_6tap_addline_15(unsigned short *src, unsigned int count,
  unsigned int *lookup);

void blit_6tap_addline_16(unsigned short *src, unsigned int count,
  unsigned int *lookup);

void blit_6tap_addline_32(unsigned int *src, unsigned int count,
  unsigned int *lookup);
  
void blit_6tap_render_line_15(unsigned short *dst0, unsigned short *dst1,
  unsigned int count);

void blit_6tap_render_line_16(unsigned short *dst0, unsigned short *dst1,
  unsigned int count);

void blit_6tap_render_line_32(unsigned int *dst0, unsigned int *dst1,
  unsigned int count);

void blit_6tap_render_line_yuy2(unsigned short *dst0, unsigned short *dst1,
  unsigned int count);

void blit_6tap_15_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_16_15(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_16_16(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_16_24(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_16_32(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_16_YUY2(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_32_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_32_16_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_32_24_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_32_32_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_32_YUY2_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

/****************************************************************************/

void blit_scan2_h_15_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_h_16_15(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_h_16_16(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_h_16_24(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_h_16_32(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_h_16_YUY2(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_h_32_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_h_32_16_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_h_32_24_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_h_32_32_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_h_32_YUY2_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

/****************************************************************************/

void blit_scan2_v_15_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_v_16_15(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_v_16_16(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_v_16_24(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_v_16_32(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_v_16_YUY2(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_v_32_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_v_32_16_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_v_32_24_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_v_32_32_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan2_v_32_YUY2_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

/****************************************************************************/

void blit_rgbscan_h_15_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_h_16_15(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_h_16_16(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_h_16_24(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_h_16_32(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_h_16_YUY2(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_h_32_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_h_32_16_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_h_32_24_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_h_32_32_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_h_32_YUY2_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

/****************************************************************************/

void blit_rgbscan_v_15_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_v_16_15(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_v_16_16(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_v_16_24(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_v_16_32(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_v_16_YUY2(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_v_32_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_v_32_16_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_v_32_24_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_v_32_32_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_rgbscan_v_32_YUY2_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

/****************************************************************************/

void blit_scan3_h_15_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_h_16_15(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_h_16_16(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_h_16_24(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_h_16_32(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_h_16_YUY2(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_h_32_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_h_32_16_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_h_32_24_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_h_32_32_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_h_32_YUY2_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

/****************************************************************************/

void blit_scan3_v_15_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_v_16_15(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_v_16_16(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_v_16_24(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_v_16_32(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_v_16_YUY2(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_v_32_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_v_32_16_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_v_32_24_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_v_32_32_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_scan3_v_32_YUY2_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

/****************************************************************************/

void blit_fakescan_h_15_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_fakescan_h_16_16(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_fakescan_h_16_24(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_fakescan_h_16_32(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_fakescan_h_16_YUY2(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_fakescan_h_32_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_fakescan_h_32_16_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_fakescan_h_32_24_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_fakescan_h_32_32_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_fakescan_h_32_YUY2_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

/****************************************************************************/

void blit_fakescan_v_15_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_fakescan_v_16_16(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_fakescan_v_16_24(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_fakescan_v_16_32(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_fakescan_v_16_YUY2(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_fakescan_v_32_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_fakescan_v_32_16_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_fakescan_v_32_24_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_fakescan_v_32_32_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_fakescan_v_32_YUY2_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

#ifdef EFFECT_MMX_ASM
/****************************************************************************/

void blit_scan2_h_mmx_15_15_direct(void *dst0, void *dst1, const void *src,
  unsigned count, unsigned int *u32lookup);

void blit_scan2_h_mmx_16_15(void *dst0, void *dst1, const void *src,
  unsigned count, unsigned int *u32lookup);

void blit_scan2_h_mmx_16_16(void *dst0, void *dst1, const void *src,
  unsigned count, unsigned int *u32lookup);

void blit_scan2_h_mmx_16_32(void *dst0, void *dst1, const void *src,
  unsigned count, unsigned int *u32lookup);

void blit_scan2_h_mmx_32_32_direct(void *dst0, void *dst1, const void *src,
  unsigned count, unsigned int *u32lookup);

/****************************************************************************/

void blit_6tap_mmx_addline_15(unsigned short *src, unsigned int count,
  unsigned int *lookup);

void blit_6tap_mmx_addline_16(unsigned short *src, unsigned int count,
  unsigned int *lookup);

void blit_6tap_mmx_addline_32(unsigned int *src, unsigned int count,
  unsigned int *lookup);
  
void blit_6tap_mmx_render_line_15(unsigned short *dst0, unsigned short *dst1,
  unsigned int count);

void blit_6tap_mmx_render_line_16(unsigned short *dst0, unsigned short *dst1,
  unsigned int count);

void blit_6tap_mmx_render_line_32(unsigned int *dst0, unsigned int *dst1,
  unsigned int count);

/* no mmx to yuy2 version */
#define blit_6tap_mmx_render_line_yuy2 blit_6tap_render_line_yuy2

void blit_6tap_mmx_15_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_mmx_16_15(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_mmx_16_16(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_mmx_16_24(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_mmx_16_32(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_mmx_16_YUY2(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_mmx_32_15_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_mmx_32_16_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_mmx_32_24_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_mmx_32_32_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

void blit_6tap_mmx_32_YUY2_direct(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

#endif

#endif
