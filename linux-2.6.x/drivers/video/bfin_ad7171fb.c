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
#include <asm/board/cdefBF533.h>
#include <asm/irq.h>
#include <linux/timer.h>

#define BFIN_FB_PHYS rgb_buffer
#define BFIN_FB_PHYS_LEN 756000
#define BFIN_FB_YCRCB_LEN 1512000
#define CONFIG_VIDEO_BLACKFIN_PPI_IRQ IRQ_PPI
#define CONFIG_VIDEO_BLACKFIN_PPI_IRQ_ERR IRQ_DMA_ERROR
char *rgb_buffer = 0 ;
char *ycrcb_buffer = 0 ;
int id ;

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
static int bfin_mmap(struct fb_info *info, struct file *file, struct vm_area_struct * vma);

extern void _NtscVideoOutFrameBuffInit(void *, void *);
extern void _NtscVideoOutBuffUpdate(void *, void *);
extern void _Flash_Setup_ADV_Reset(void);
extern void _config_dma(void *buffer);
extern void _config_ppi(void);

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
	.xres		= 360,
	.yres		= 524,
	.xres_virtual	= 360,
	.yres_virtual	= 524,
	.bits_per_pixel	= 32,	
	.activate	= FB_ACTIVATE_TEST,
	.height		= -1,
	.width		= -1,
	.left_margin	= 16,
	.right_margin	= 22,
	.upper_margin	= 25,
	.lower_margin	= 64,
	.vmode		= FB_VMODE_INTERLACED,
};

static struct fb_fix_screeninfo bfin_ad7171_fb_fix __initdata = {
	.id		= "BFIN 7171",
	.smem_len	= BFIN_FB_PHYS_LEN,
	.type		= FB_TYPE_PACKED_PIXELS,
	.visual		= FB_VISUAL_DIRECTCOLOR,
	.xpanstep	= 0,
	.ypanstep	= 0,
	.line_length	= 1440,
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
	.fb_mmap	= bfin_mmap,
};

struct timer_list buffer_swapping_timer ;

irqreturn_t __attribute((section(".text.l1")))
ppi_handler(int irq,
            void *dev_id,
            struct pt_regs *regs)
{
  *pDMA0_IRQ_STATUS |= 1;
  return IRQ_HANDLED;
}

void 
rgbsetup(int *rgb)			//This function sets up colour patter in ycrcb buffer
{ 
	int i=0 , j, black =0, yellow = 0x00ff00ff, red = 0x000000ff, blue = 0xff00ff00, green = 0x00ff0000, offset = 37800;

	for(i=0; i<188640; i++)
		rgb[i] = 0xffffffff;
	for(j=1; j<=105;){
		for(i=0; i<360; i++)
		{
			rgb[offset * 0 + i + j * 360] = yellow;		// j = line no., i = pixel no. in that particular line
			rgb[offset * 1 + i + j * 360] = black;			
			rgb[offset * 2 + i + j * 360] = red;
			rgb[offset * 3 + i + j * 360] = blue;
			rgb[offset * 4 + i + j * 360] = green;
		}
		j += 1;
 	}                 
}                                                                               

static int 
bfin_mmap(struct fb_info *info, struct file *file, struct vm_area_struct * vma)
{
  /* we really dont need any map ... not sure how the smem_start will
     end up in the kernel
  */
	return((int)rgb_buffer) ;
}

/* copied from vga16, do nothing setup! */
int bfin_ad7171_fb_setup(char *options)
{
	char *this_opt;
	
	if (!options || !*options)
		return 0;
	
	while ((this_opt = strsep(&options, ",")) != NULL) {
		if (!*this_opt) continue;
	}
	return 0;
}

static void timerfunction(unsigned long ptr);
static void timer_setup(void);
int __init bfin_ad7171_fb_init(void)
{
	int ret = 0;

	printk("bfin_ad7171_fb: initializing:\n");
	ycrcb_buffer = (char *)kmalloc(BFIN_FB_YCRCB_LEN, GFP_KERNEL);
	rgb_buffer = (char *)kmalloc(BFIN_FB_PHYS_LEN , GFP_KERNEL);

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
	bfin_ad7171_fb_fix.smem_start	= (int)BFIN_FB_PHYS;
	bfin_ad7171_fb.fix = bfin_ad7171_fb_fix;
	bfin_ad7171_fb.par = &bfin_par;
	bfin_ad7171_fb.flags = FBINFO_DEFAULT;

	if (register_framebuffer(&bfin_ad7171_fb) < 0) {
		printk(KERN_ERR "bfin_ad7171_fb: unable to register framebuffer\n");
		ret = -EINVAL;
	}
	printk(KERN_INFO "fb%d: %s frame buffer device\n",
	       bfin_ad7171_fb.node, bfin_ad7171_fb.fix.id);
	return ret;
}
static void __attribute((section(".text.l1")))
timerfunction(unsigned long ptr)
{
	_NtscVideoOutBuffUpdate(ycrcb_buffer, rgb_buffer);
	timer_setup();
        add_timer(&buffer_swapping_timer) ;
}

void
timer_setup(void)
{
        /*** Initialize the timer structure***/
        init_timer(&buffer_swapping_timer) ;
        buffer_swapping_timer.function = timerfunction ;
        buffer_swapping_timer.expires = jiffies + HZ*1 ;
        /***Initialisation ends***/
}

static int bfin_ad7171_fb_open(struct fb_info *info, int user)
{
        if( request_irq(CONFIG_VIDEO_BLACKFIN_PPI_IRQ, &ppi_handler, SA_SHIRQ, "PPI Data", &id ) ){
                printk( KERN_ERR "Unable to allocate ppi IRQ %d\n", CONFIG_VIDEO_BLACKFIN_PPI_IRQ);
                return -ENODEV;
        }
	bfin_ad7171_fb.screen_base = (void *)rgb_buffer;
	bfin_ad7171_fb_fix.smem_start = (int)rgb_buffer;
	if (!bfin_ad7171_fb.screen_base) {
		printk("bfin_ad7171_fb: unable to map device\n");
		return -ENOMEM;
	}
	_Flash_Setup_ADV_Reset() ;
	_config_ppi() ;
	_config_dma(ycrcb_buffer) ;
	rgbsetup((int *)rgb_buffer);
	printk("ycrcb_buffer = %p\n",ycrcb_buffer);
	printk("rgb_buffer = %p\n",rgb_buffer) ;

	_NtscVideoOutFrameBuffInit(ycrcb_buffer, rgb_buffer);
	timer_setup() ;
	enable_irq(CONFIG_VIDEO_BLACKFIN_PPI_IRQ);
        // enable the dma
        *pDMA0_CONFIG |= 1;
        *pPPI_CONTROL |= 1;
printk("PPI transfer initialized\n");
	add_timer(&buffer_swapping_timer) ;
	return 0;
}

static int bfin_ad7171_fb_release(struct fb_info *info, int user)
{
	//disable PPI 
	*pPPI_CONTROL &= 0xfffe;
	//Reset PPI
	*pPPI_CONTROL &= 0x0000;
	//Disable DMA
	*pDMA0_CONFIG &= 0xfffe;
	//Reset DMA0
	*pDMA0_CONFIG &= 0x0000;

	//Reset DMA0
	//Release the interrupt.
	disable_irq(CONFIG_VIDEO_BLACKFIN_PPI_IRQ);
	del_timer_sync(&buffer_swapping_timer) ;
	printk(" bfin_ad7171_fb Realeased\n") ;
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

#ifdef MODULE
MODULE_LICENSE("GPL");
module_init(bfin_ad7171_fb_init);
#endif
module_exit(bfin_ad7171_fb_exit);


/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-basic-offset: 8
 * End:
 */

