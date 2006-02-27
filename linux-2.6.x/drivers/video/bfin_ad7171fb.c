/*
 * linux/drivers/video/bfin_ad7171.c -- Analog Devices Blackfin + AD7171 video out chip
 * 
 * Based on vga16fb.cCopyright 1999 Ben Pfaff <pfaffben@debian.org> and Petr Vandrovec <VANDROVE@vc.cvut.cz>
 * Copyright 2004 Ashutosh Kumar Singh (ashutosh.singh@rrap-software.com)
 *
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file COPYING in the main directory of this
 * archive for more details.  
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/fb.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <asm/blackfin.h>
#include <asm/irq.h>
#include <asm/dma.h>
#include <linux/dma-mapping.h>

#include "bfin_ad7171fb.h"
#define RGB_WIDTH	720
#define RGB_HEIGHT	480
#define YCBCR_WIDTH	1716
#define YCBCR_HEIGHT	525
#define LEFT_MARGIN	276
#define UPPER_MARGIN	22
#define BFIN_FB_PHYS_LEN (RGB_WIDTH*RGB_HEIGHT*sizeof(struct rgb_t))
#define BFIN_FB_YCRCB_LEN (YCBCR_WIDTH*YCBCR_HEIGHT)
#define CONFIG_VIDEO_BLACKFIN_PPI_IRQ IRQ_PPI
#define CONFIG_VIDEO_BLACKFIN_PPI_IRQ_ERR IRQ_DMA_ERROR
struct rgb_t *rgb_buffer = 0 ;
struct ycrcb_t *ycrcb_buffer = 0 ;
unsigned char *rgb_l1;
unsigned char *yuv_l1;
struct timer_list bfin_framebuffer_timer;
int id1 ;

static int bfin_ad7171_fb_open(struct fb_info *info, int user);
static int bfin_ad7171_fb_release(struct fb_info *info, int user);
static int bfin_ad7171_fb_check_var(struct fb_var_screeninfo *var,
			     struct fb_info *info);
static int bfin_ad7171_fb_set_par(struct fb_info *info);
static int bfin_ad7171_fb_pan_display(struct fb_var_screeninfo *var,
			       struct fb_info *info) ;
static void bfin_ad7171_fb_fillrect(struct fb_info *info, const struct fb_fillrect *rect);
static void bfin_ad7171_fb_imageblit(struct fb_info *info, const struct fb_image *image);
static int bfin_ad7171_fb_blank(int blank, struct fb_info *info);
static int bfin_fb_mmap(struct fb_info *info, struct file *file, struct vm_area_struct * vma);

static void bfin_config_ppi(void);
static void bfin_config_dma(void *ycrcb_buffer);
static void bfin_enable_ppi(void);
static void bfin_framebuffer_init(void *ycrcb_buffer);
static void bfin_framebuffer_logo(void *ycrcb_buffer);
extern void bfin_framebuffer_update(struct ycrcb_t *ycrcb_buffer, struct rgb_t *rgb_buffer)__attribute((section(".text.l1")));
static void bfin_framebuffer_timer_setup(void);
static void bfin_framebuffer_timerfn(unsigned long data);
extern void rgb2yuv(unsigned char rgb[], unsigned char yuv[], int n)__attribute((section(".text.l1")));
extern void dma_memcpy(void * dest,const void *src,size_t count)__attribute((section(".text.l1")));
extern unsigned long l1_data_A_sram_alloc(unsigned long size);
extern int l1_data_A_sram_free(unsigned long addr);

/* --------------------------------------------------------------------- */

/*
 * card parameters
 */

static struct fb_info bfin_ad7171_fb; 

static struct bfin_ad7171_fb_par {
	/* structure holding blackfin / ad7171 paramters when
           screen is blanked */
	struct {
		unsigned char	Mode;		/* ntsc/pal/? */
	} vga_state;
	atomic_t ref_count;
} bfin_par;

/* --------------------------------------------------------------------- */

static struct fb_var_screeninfo bfin_ad7171_fb_defined = {
	.xres		= RGB_WIDTH,
	.yres		= RGB_HEIGHT,
	.xres_virtual	= RGB_WIDTH,
	.yres_virtual	= RGB_HEIGHT,
	.bits_per_pixel	= 24,	
	.activate	= FB_ACTIVATE_TEST,
	.height		= -1,
	.width		= -1,
	.left_margin	= LEFT_MARGIN,
	.right_margin	= 0,
	.upper_margin	= UPPER_MARGIN,
	.lower_margin	= 0,
	.vmode		= FB_VMODE_INTERLACED,
};

static struct fb_fix_screeninfo bfin_ad7171_fb_fix __initdata = {
	.id		= "BFIN 7171",
	.smem_len	= BFIN_FB_PHYS_LEN,
	.type		= FB_TYPE_PACKED_PIXELS,
	.visual		= FB_VISUAL_DIRECTCOLOR,
	.xpanstep	= 0,
	.ypanstep	= 0,
	.line_length	= RGB_WIDTH*3,
	.accel		= FB_ACCEL_NONE
};

static struct fb_ops bfin_ad7171_fb_ops = {
	.owner		= THIS_MODULE,
	.fb_open        = bfin_ad7171_fb_open,
	.fb_release     = bfin_ad7171_fb_release,
	.fb_check_var	= bfin_ad7171_fb_check_var,
	.fb_set_par	= bfin_ad7171_fb_set_par,
	.fb_pan_display = bfin_ad7171_fb_pan_display,
	.fb_blank 	= bfin_ad7171_fb_blank,
	.fb_fillrect	= bfin_ad7171_fb_fillrect,
	.fb_imageblit	= bfin_ad7171_fb_imageblit,
	.fb_cursor      = soft_cursor,
	.fb_mmap	= bfin_fb_mmap,
};

static void bfin_framebuffer_timer_setup(void)
{
	init_timer(&bfin_framebuffer_timer) ;
        bfin_framebuffer_timer.function = bfin_framebuffer_timerfn ;
        bfin_framebuffer_timer.expires = jiffies + 10 ;
	add_timer(&bfin_framebuffer_timer);
}

static void bfin_framebuffer_timerfn(unsigned long data)
{
	bfin_framebuffer_update(ycrcb_buffer, rgb_buffer);
	bfin_framebuffer_timer_setup();
}
	

static int bfin_fb_mmap(struct fb_info *info, struct file *file, struct vm_area_struct * vma)
{
  /* we really dont need any map ... not sure how the smem_start will
     end up in the kernel
  */
	vma->vm_start  = (int)rgb_buffer;
	return (int)rgb_buffer;
}

static void bfin_framebuffer_init(void *ycrcb_buffer)
{
        const int nNumNTSCVoutFrames = 1;  // changed from 2 to 1 (dkl)
        const int nNumNTSCLines = 525;
        char *dest = (void *)ycrcb_buffer;
                                                                                                                                                             
        int nFrameNum, lines;
                                                                                                                                                             
        for ( nFrameNum = 0; nFrameNum < nNumNTSCVoutFrames; ++nFrameNum )
        {
                for ( lines = 1; lines <= nNumNTSCLines; lines++ )
                {
                        int offset = 0;
			unsigned int code;
                        int i;

			if(lines<=3 || (lines>=266 && lines <=282))
				offset = 0;
			if((lines>=4 && lines<=19) || (lines>=264 && lines<=265))
				offset = 1;
			if(lines>=20 && lines<=263)
				offset = 2;
			if(lines>=283 && lines<=525)
				offset = 3;
                                                                                                                                                             
                        /* Output EAV code */
                        code = system_code_map[ offset ].eav;
                        *dest++ = (char) (code >> 24) & 0xff;
                        *dest++ = (char) (code >> 16) & 0xff;
                        *dest++ = (char) (code >> 8) & 0xff;
                        *dest++ = (char) (code) & 0xff;
                                                                                                                                                             
                        /* Output horizontal blanking */
                        for ( i = 0; i < 67*2; ++i )
                        {
                                *dest++ = 0x80;
                                *dest++ = 0x10;
                        }
                                                                                                                                                             
                        /* Output SAV */
                        code = system_code_map[ offset ].sav;
                        *dest++ = (char) (code >> 24) & 0xff;
                        *dest++ = (char) (code >> 16) & 0xff;
                        *dest++ = (char) (code >> 8) & 0xff;
                        *dest++ = (char) (code) & 0xff;
                                                                                                                                                             
                        /* Output empty horizontal data */
                        for ( i = 0; i < 360*2; ++i )
                        {
                                *dest++ = 0x80;
                                *dest++ = 0x10;
                        }
                }
        }
}

static void bfin_framebuffer_logo(void *ycrcb_buffer) 
{
        int *OddPtr32;
        int OddLine;
        int *EvenPtr32;
        int EvenLine;
        int i;

        /* fill odd and even frames */
        for (OddLine = 22, EvenLine = 285; OddLine < 263; OddLine++, EvenLine++) {
                OddPtr32 = (int *)((ycrcb_buffer + (OddLine * 1716)) + 276);
                EvenPtr32 = (int *)((ycrcb_buffer + (EvenLine * 1716)) + 276);
                for (i = 0; i < 360; i++, OddPtr32++, EvenPtr32++) {
                        *OddPtr32 = BLUE;
                        *EvenPtr32 = BLUE;
                        }
        }
}

void bfin_framebuffer_update(struct ycrcb_t *ycrcb_buffer, struct rgb_t *rgb_buffer)
{
	unsigned char *rgb_base  = (unsigned char *)rgb_buffer;
	unsigned char *ycrcb_base = (unsigned char *)ycrcb_buffer;
	unsigned char *odd_yuv;
	unsigned char *even_yuv;
	unsigned char *rgb_ptr;
	int oddline, evenline,rgbline;
	
        for(oddline = 22, evenline = 285, rgbline = 0; 
		oddline < 22+RGB_HEIGHT/2; oddline ++, evenline ++){
		odd_yuv= (unsigned char *)((ycrcb_base + (oddline * 1716))+276);
		rgb_ptr = (unsigned char *)(rgb_base + (rgbline++)*RGB_WIDTH*3);
		dma_memcpy(rgb_l1,rgb_ptr,RGB_WIDTH*3);
		rgb2yuv(rgb_l1,yuv_l1,RGB_WIDTH);
		dma_memcpy(odd_yuv, yuv_l1, RGB_WIDTH*2);

		even_yuv = (unsigned char *)((ycrcb_base + (evenline * 1716))+276);
		rgb_ptr = (unsigned char *)(rgb_base + (rgbline++)*RGB_WIDTH*3);
		dma_memcpy(rgb_l1,rgb_ptr,RGB_WIDTH*3);
                rgb2yuv(rgb_l1,yuv_l1,RGB_WIDTH);
                dma_memcpy(even_yuv, yuv_l1, RGB_WIDTH*2);
	}
}

static void bfin_rgb_buffer_init(struct rgb_t *rgb_buffer, int width, int height)
{
	struct rgb_t *rgb_ptr = rgb_buffer;
	int i;
	/* the first block */
	for(i=0;i<width*height/4;i++){
		rgb_ptr->r = 0x00;
                rgb_ptr->g = 0x00;
                rgb_ptr->b = 0x00;
                rgb_ptr++;
	}
	/* the second block */
        for(;i<width*height/2;i++){
                rgb_ptr->r = 0x00;
                rgb_ptr->g = 0x00;
                rgb_ptr->b = 0x00;
                rgb_ptr++;
        }
	
	/* the third block */
        for(;i<width*height*3/4;i++){
                rgb_ptr->r = 0x00;
                rgb_ptr->g = 0x00;
                rgb_ptr->b = 0x00;
                rgb_ptr++;
        }
	
	/* the fourth block */
	for(;i<width*height;i++){
		rgb_ptr->r = 0x00;
		rgb_ptr->g = 0x00;
		rgb_ptr->b = 0x00;
		rgb_ptr++;
	}
}
	
static void bfin_config_dma(void *ycrcb_buffer)
{	
        *pDMA0_START_ADDR       = ycrcb_buffer;
        *pDMA0_X_COUNT          = 0x035A;
        *pDMA0_X_MODIFY         = 0x0002;
        *pDMA0_Y_COUNT          = 0x020D;
        *pDMA0_Y_MODIFY         = 0x0002;
        *pDMA0_CONFIG           = 0x1015;
}

void dma_memcpy(void * dest,const void *src,size_t count)
{

                while(*pMDMA_D0_IRQ_STATUS & DMA_RUN);
		
		*pMDMA_D0_IRQ_STATUS = DMA_DONE | DMA_ERR;

                /* Copy sram functions from sdram to sram */
                /* Setup destination start address */
                *pMDMA_D0_START_ADDR = (volatile void **)dest;
                /* Setup destination xcount */
                *pMDMA_D0_X_COUNT = count ;
                /* Setup destination xmodify */
                *pMDMA_D0_X_MODIFY = 1;

                /* Setup Source start address */
                *pMDMA_S0_START_ADDR = (volatile void **)src;
                /* Setup Source xcount */
                *pMDMA_S0_X_COUNT = count;
                /* Setup Source xmodify */
                *pMDMA_S0_X_MODIFY = 1;

                /* Enable source DMA */
                *pMDMA_S0_CONFIG = (DMAEN);
		__builtin_bfin_ssync();

                *pMDMA_D0_CONFIG = ( WNR | DMAEN);

                while(*pMDMA_D0_IRQ_STATUS & DMA_RUN){
                        *pMDMA_D0_IRQ_STATUS |= (DMA_DONE | DMA_ERR);
                }
                *pMDMA_D0_IRQ_STATUS |= (DMA_DONE | DMA_ERR);
}


static void bfin_config_ppi(void)
{
#ifdef CONFIG_BF537
        *pPORTG_FER   = 0xFFFF; /* PPI[15:0]    */
        *pPORTF_FER  |= 0x8380; /* PF.15 - PPI_CLK */
        *pPORT_MUX   &= ~0x0E00;
        *pPORT_MUX   |= 0x0100;
#endif
        *pPPI_CONTROL = 0x0082;
        *pPPI_FRAME   = 0x020D;
}

static void bfin_enable_ppi(void)
{
	*pPPI_CONTROL		|= PORT_EN;
}

int __init bfin_ad7171_fb_init(void)
{
	int ret = 0;
/*	dma_addr_t dma_handle;		*/

	printk(KERN_NOTICE "bfin_ad7171_fb: initializing:\n");
/*	ycrcb_buffer = (struct yuyv_t *)dma_alloc_coherent(NULL,BFIN_FB_YCRCB_LEN, &dma_handle, GFP_DMA);*/
	ycrcb_buffer = (struct ycrcb_t *)kmalloc(BFIN_FB_YCRCB_LEN, GFP_KERNEL);
	memset(ycrcb_buffer, 0, BFIN_FB_YCRCB_LEN);
	rgb_buffer = (struct rgb_t *)kmalloc(BFIN_FB_PHYS_LEN , GFP_KERNEL);
	memset(rgb_buffer, 0, BFIN_FB_PHYS_LEN);

	bfin_ad7171_fb.screen_base = (void *)rgb_buffer;
	bfin_ad7171_fb_fix.smem_start = (int)rgb_buffer;
	if (!bfin_ad7171_fb.screen_base) {
		printk("bfin_ad7171_fb: unable to map device\n");
		ret = -ENOMEM;
	}
	bfin_ad7171_fb_defined.red.length   = 8;
	bfin_ad7171_fb_defined.green.length = 8;
	bfin_ad7171_fb_defined.blue.length  = 8;	

	bfin_ad7171_fb.fbops = &bfin_ad7171_fb_ops;
	bfin_ad7171_fb.var = bfin_ad7171_fb_defined;
	/* our physical memory is dynamically allocated */
	bfin_ad7171_fb_fix.smem_start	= (int)rgb_buffer;
	bfin_ad7171_fb.fix = bfin_ad7171_fb_fix;
	bfin_ad7171_fb.par = &bfin_par;
	bfin_ad7171_fb.flags = FBINFO_DEFAULT;

	if (register_framebuffer(&bfin_ad7171_fb) < 0) {
		printk(KERN_ERR "bfin_ad7171_fb: unable to register framebuffer\n");
		ret = -EINVAL;
	}
	printk(KERN_INFO "fb%d: %s frame buffer device\n",
	       bfin_ad7171_fb.node, bfin_ad7171_fb.fix.id);
	printk(KERN_INFO "fb memory address : 0x%p\n",rgb_buffer);
	return ret;
}

static int bfin_ad7171_fb_open(struct fb_info *info, int user)
{
	rgb_l1 = (unsigned char *)l1_data_A_sram_alloc(RGB_WIDTH*3);
	if(!rgb_l1){
		printk("alloc rgb l1 buffer failed\n");
		return -ENOMEM;
	}
        yuv_l1 = (unsigned char *)l1_data_A_sram_alloc(RGB_WIDTH*2);
	if(!yuv_l1){
		printk("alloc YCbCr l1 buffer failed\n");
		return -ENOMEM;
	}

	bfin_ad7171_fb.screen_base = (void *)rgb_buffer;
	bfin_ad7171_fb_fix.smem_start = (int)rgb_buffer;
	if (!bfin_ad7171_fb.screen_base) {
		printk("bfin_ad7171_fb: unable to map device\n");
		return -ENOMEM;
	}

        bfin_framebuffer_init(ycrcb_buffer);
        bfin_framebuffer_logo(ycrcb_buffer);
	bfin_rgb_buffer_init(rgb_buffer,RGB_WIDTH,RGB_HEIGHT);
	bfin_framebuffer_timer_setup();
 	bfin_config_ppi();
	bfin_config_dma(ycrcb_buffer);
	bfin_enable_ppi();
	return 0;
}

static int bfin_ad7171_fb_release(struct fb_info *info, int user)
{
	if(rgb_l1)
		l1_data_A_sram_free((unsigned long)rgb_l1);
	if(yuv_l1)
		l1_data_A_sram_free((unsigned long)yuv_l1);
	del_timer(&bfin_framebuffer_timer);
	return 0;
}

static int bfin_ad7171_fb_check_var(struct fb_var_screeninfo *var,
			     struct fb_info *info)
{
	printk("bfin_ad7171_fb Variables checked\n") ;
	return -EINVAL;
}

static int bfin_ad7171_fb_set_par(struct fb_info *info)
{
	printk("bfin_ad7171_fb_set_par called not implemented\n") ; 
	return -EINVAL;
}


static int bfin_ad7171_fb_pan_display(struct fb_var_screeninfo *var,
			       struct fb_info *info) 
{
	printk("bfin_ad7171_fb_pan_display called ... not implemented\n");
	return -EINVAL;
}

/* 0 unblank, 1 blank, 2 no vsync, 3 no hsync, 4 off */
static int bfin_ad7171_fb_blank(int blank, struct fb_info *info)
{
printk("bfin_ad7171_fb_blank called ... not implemented\n");
	return -EINVAL;
}

static void bfin_ad7171_fb_fillrect(struct fb_info *info, const struct fb_fillrect *rect)
{
printk("bfin_ad7171_fb_fillrect called ... not implemented\n");
}

static void bfin_ad7171_fb_imageblit(struct fb_info *info, const struct fb_image *image)
{
printk("bfin_ad7171_fb_imageblit called ... not implemented\n");
}

static void __exit bfin_ad7171_fb_exit(void)
{
    unregister_framebuffer(&bfin_ad7171_fb);
}

MODULE_LICENSE("GPL");
module_init(bfin_ad7171_fb_init);
module_exit(bfin_ad7171_fb_exit);
