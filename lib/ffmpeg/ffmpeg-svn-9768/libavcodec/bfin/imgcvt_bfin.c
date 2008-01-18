#include "avcodec.h"
#include "dsputil.h"

typedef struct ConvertEntry {
    void (*convert)(AVPicture *dst,
                    const AVPicture *src, int width, int height);
} ConvertEntry;

static void yuyv2yuv420p (AVPicture *dst, const AVPicture *src, int width, int height)
{
    ff_bfin_yuyvtoyv12 (src->data[0], dst->data[0], dst->data[1], dst->data[2],
                        width, height,
                        dst->linesize[0], dst->linesize[1], src->linesize[0]);
}

static void uyvy2yuv420p (AVPicture *dst, const AVPicture *src, int width, int height)
{
    ff_bfin_uyvytoyv12 (src->data[0], dst->data[0], dst->data[1], dst->data[2],
                        width, height,
                        dst->linesize[0], dst->linesize[1], src->linesize[0]);
}

void ff_bfin_img_convert_init (ConvertEntry *convert_table) {
    if (convert_table) {
        convert_table[PIX_FMT_NB*(PIX_FMT_YUYV422)+PIX_FMT_YUV420P].convert = yuyv2yuv420p;
        convert_table[PIX_FMT_NB*(PIX_FMT_UYVY422)+PIX_FMT_YUV420P].convert = uyvy2yuv420p;
    }
}
