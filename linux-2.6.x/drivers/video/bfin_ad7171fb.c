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

char *rgb_buffer = 0;
char *ycrcb_buffer = 0;
#define BFIN_FB_PHYS rgb_buffer
#define BFIN_FB_PHYS_LEN 756000
#define BFIN_FB_YCRCB_LEN 1512000
#define CONFIG_VIDEO_BLACKFIN_PPI_IRQ IRQ_PPI
#define CONFIG_VIDEO_BLACKFIN_PPI_IRQ_ERR IRQ_DMA_ERROR


//extern char *rgb_buffer; // should be allocated elsewhere or in the init function here
/* forward declarations */
static void vga16fb_pan_var(struct fb_info *info, 
			    struct fb_var_screeninfo *var);
static void vga16fb_update_fix(struct fb_info *info);
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
	.xres_virtual	= 320,
	.yres_virtual	= 524,
	.bits_per_pixel	= 32,	
	.activate	= FB_ACTIVATE_TEST,
	.height		= -1,
	.width		= -1,
	//.pixclock	= 39721,
	//.left_margin	= 48,
	//.right_margin	= 16,
	//.upper_margin	= 39,
	//.lower_margin	= 8,
	//.hsync_len 	= 96,
	//.vsync_len	= 2,
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
  rgbsetup(char *rgb)			//This function sets up colour patter in ycrcb buffer
{ 
	int j, i=0 ,r0=0,r1=255;

	
	
        
       

	for (j=0; j<37800; j++)
	{
		rgb[i++] = r0;
		rgb[i++] = r0;
		rgb[i++] = r0;
		rgb[i++] = r0;

		         
 	}                 

	for (j=0; j<37800; j++)
	{
		rgb[i++] = r1;
		rgb[i++] = r0;
		rgb[i++] = r1;
		rgb[i++] = r0;
        }   
       for (j=0; j<37800; j++)
        
       {                                                                                       

                 rgb[i++] = r1;
                 rgb[i++] = r0;
                 rgb[i++] = r0;
                 rgb[i++] = r0;
       }
      for (j=0; j<37800; j++)
      {
                 rgb[i++] = r0;
                 rgb[i++] = r1;
                 rgb[i++] = r0;
                 rgb[i++] = r1;

       }

       for (j=0; j<37800; j++)

      {
                  rgb[i++] = r0;
                  rgb[i++] = r0;
                  rgb[i++] = r1;
                  rgb[i++] = r0;
      }

}                                                                               
static int 
bfin_mmap(struct fb_info *info, struct file *file, struct vm_area_struct * vma)
{
  /* we really dont need any map ... not sure how the smem_start will
     end up in the kernel
  */
	return(rgb_buffer) ;
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
	int i;
	int ret;

printk("bfin_ad7171_fb: initializing:\n");
	ycrcb_buffer = (char *)kmalloc(BFIN_FB_YCRCB_LEN, GFP_KERNEL);
	rgb_buffer = (char *)kmalloc(BFIN_FB_PHYS_LEN , GFP_KERNEL);
printk("allocated %x\n", rgb_buffer);
	bfin_ad7171_fb.screen_base = (void *)rgb_buffer;
	bfin_ad7171_fb_fix.smem_start = (void *)rgb_buffer;
	if (!bfin_ad7171_fb.screen_base) {
		printk("bfin_ad7171_fb: unable to map device\n");
		ret = -ENOMEM;
		goto err_ioremap;
	}
	printk("bfin_ad7171_fb: mapped to 0x%p\n");

	bfin_ad7171_fb_defined.red.length   = 8;
	bfin_ad7171_fb_defined.green.length = 8;
	bfin_ad7171_fb_defined.blue.length  = 8;	

	bfin_ad7171_fb.fbops = &bfin_ad7171_fb_ops;
	bfin_ad7171_fb.var = bfin_ad7171_fb_defined;

	/* our physical memory is dynamically allocated */
	bfin_ad7171_fb_fix.smem_start	= BFIN_FB_PHYS;
	bfin_ad7171_fb.fix = bfin_ad7171_fb_fix;
	bfin_ad7171_fb.par = &bfin_par;
	bfin_ad7171_fb.flags = FBINFO_DEFAULT;

#if 0 /* TODO : do we need a colormap? */
	i = (bfin_ad7171_fb_defined.bits_per_pixel == 8) ? 256 : 16;
	ret = fb_alloc_cmap(&bfin_ad7171_fb.cmap, i, 0);
	if (ret) {
		printk(KERN_ERR "bfin_ad7171_fb: unable to allocate colormap\n");
		ret = -ENOMEM;
		goto err_alloc_cmap;
	}
#endif

	if (register_framebuffer(&bfin_ad7171_fb) < 0) {
		printk(KERN_ERR "bfin_ad7171_fb: unable to register framebuffer\n");
		ret = -EINVAL;
		goto err_check_var;
	}

	printk(KERN_INFO "fb%d: %s frame buffer device\n",
	       bfin_ad7171_fb.node, bfin_ad7171_fb.fix.id);

	return 0;
 err_check_var:
	
 err_alloc_cmap:
	iounmap(bfin_ad7171_fb.screen_base);
 err_ioremap:
	return ret;
}
static void __attribute((section(".text.l1")))
timerfunction(unsigned long ptr)
{
//	_NtscVideoOutBuffUpdate(ycrcb_buffer, rgb_buffer);
	_NtscVideoOutFrameBuffInit(ycrcb_buffer, rgb_buffer);
	timer_setup();
        add_timer(&buffer_swapping_timer) ;
}


void
timer_setup(void)
{

        /*** Initialize the timer structure***/

        init_timer(&buffer_swapping_timer) ;
        buffer_swapping_timer.function = timerfunction ;
        buffer_swapping_timer.expires = jiffies + HZ*2 ;

        /***Initialisation ends***/

}


static void vga16fb_pan_var(struct fb_info *info, 
			    struct fb_var_screeninfo *var)
{
printk("vga16fb_pan_var called ... not implemented\n");

}

static void vga16fb_update_fix(struct fb_info *info)
{
printk("vga16fb_update_fix called ... not implemented\n");
}

static int bfin_ad7171_fb_open(struct fb_info *info, int user)
{
/*******It is needed to check the status of devices and do it accordingly...but for the current purpose lets skip it.*********/
        if( request_irq(CONFIG_VIDEO_BLACKFIN_PPI_IRQ, &ppi_handler, SA_SHIRQ, "PPI Data", NULL ) ){
                printk( KERN_ERR "Unable to allocate ppi IRQ %d\n", CONFIG_VIDEO_BLACKFIN_PPI_IRQ);
                return -ENODEV;
        }
	rgbsetup(rgb_buffer);
printk("ycrcb_buffer = %x\n",ycrcb_buffer);
printk("rgb_buffer = %x\n",rgb_buffer) ;
	_NtscVideoOutFrameBuffInit(ycrcb_buffer, rgb_buffer);
	
	_Flash_Setup_ADV_Reset() ;
	_config_ppi() ;
	_config_dma(ycrcb_buffer) ;
	timer_setup() ;
	enable_irq(CONFIG_VIDEO_BLACKFIN_PPI_IRQ);
        // enable the dma
        *pDMA0_CONFIG |= 1;
        *pPPI_CONTROL |= 1;
	add_timer(&buffer_swapping_timer) ;
	return 0;
}

static int bfin_ad7171_fb_release(struct fb_info *info, int user)
{
	//disable DMA
	*pPPI_CONTROL &= 0;
	*pDMA0_CONFIG &= 0;
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
	return 0;
}

static int bfin_ad7171_fb_set_par(struct fb_info *info)
{
	printk("Parameters are set\n") ; 
	return 0;
}


static int bfin_ad7171_fb_pan_display(struct fb_var_screeninfo *var,
			       struct fb_info *info) 
{
	printk("bfin_ad7171_fb_pan_display called ... not implemented\n");
	return 0;
}

/* 0 unblank, 1 blank, 2 no vsync, 3 no hsync, 4 off */
static int bfin_ad7171_fb_blank(int blank, struct fb_info *info)
{
	struct bfin_ad7171_fb_par *par = (struct bfin_ad7171_fb_par *) info->par;
printk("bfin_ad7171_fb_blank called ... not implemented\n");
return 0;

	switch (blank) {
	case 0:				/* Unblank */
		break;
	case 1:				/* blank */
		break;
	default:			/* VESA blanking */
		break;
	}
	return 0;
}

static void bfin_ad7171_fb_fillrect(struct fb_info *info, const struct fb_fillrect *rect)
{
	int vxres, vyres;
	int x2, y2, width;

printk("bfin_ad7171_fb_fillrect called ... not implemented\n");
return;
	vxres = info->var.xres_virtual;
	vyres = info->var.yres_virtual;

	if (!rect->width || !rect->height || rect->dx > vxres || rect->dy > vyres)
		return;

	/* We could use hardware clipping but on many cards you get around
	 * hardware clipping by writing to framebuffer directly. */

	x2 = rect->dx + rect->width;
	y2 = rect->dy + rect->height;
	x2 = x2 < vxres ? x2 : vxres;
	y2 = y2 < vyres ? y2 : vyres;
	width = x2 - rect->dx;

}

static void bfin_ad7171_fb_imageblit(struct fb_info *info, const struct fb_image *image)
{
printk("bfin_ad7171_fb_imageblit called ... not implemented\n");
/*
	if (image->depth == 1)
	else if (image->depth <= info->var.bits_per_pixel)
*/
}

static void __exit bfin_ad7171_fb_exit(void)
{
    unregister_framebuffer(&bfin_ad7171_fb);
    //iounmap(bfin_ad7171_fb.screen_base);
    //fb_dealloc_cmap(&bfin_ad7171_fb.cmap);
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

