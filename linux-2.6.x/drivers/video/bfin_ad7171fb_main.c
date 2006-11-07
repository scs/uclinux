/*
 * linux/drivers/video/bfin_ad7171.c -- Analog Devices Blackfin + AD7171 video out chip
 *
 * Based on vga16fb.c: Copyright 1999 Ben Pfaff <pfaffben@debian.org> and Petr Vandrovec <VANDROVE@vc.cvut.cz>
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
#define BFIN_FB_PHYS_LEN (RGB_WIDTH*RGB_HEIGHT*sizeof(struct rgb_t))
#define BFIN_FB_YCRCB_LEN (YCBCR_WIDTH*YCBCR_HEIGHT)
#define CONFIG_VIDEO_BLACKFIN_PPI_IRQ IRQ_PPI
#define CONFIG_VIDEO_BLACKFIN_PPI_IRQ_ERR IRQ_DMA_ERROR

#ifndef CONFIG_VIDEO_V4L1_COMPAT
#define VIDEO_MODE_PAL          0
#define VIDEO_MODE_NTSC         1
#endif

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
static int bfin_fb_mmap(struct fb_info *info, struct vm_area_struct * vma);

static void bfin_config_ppi(void);
static void bfin_config_dma(void *ycrcb_buffer);
static void bfin_disable_dma(void);
static void bfin_enable_ppi(void);
static void bfin_disable_ppi(void);
static void bfin_framebuffer_init(void *ycrcb_buffer);
extern void bfin_framebuffer_update(struct ycrcb_t *ycrcb_buffer,
				struct rgb_t *rgb_buffer)__attribute__((l1_text));
extern void rgb2yuv(unsigned char rgb[], unsigned char yuv[],
				int n)__attribute__((l1_text));
extern void fb_memcpy(unsigned int * dest,unsigned int *src,
				size_t count)__attribute__((l1_text));
static void bfin_framebuffer_timer_setup(void);
static void bfin_framebuffer_timerfn(unsigned long data);
/*
 * I2C driver
 */
#include <linux/i2c.h>
#include <linux/i2c-dev.h>

#define I2C_NAME(x) (x)->name

#include <linux/video_encoder.h>
#include <linux/videodev.h>

static inline int adv7171_write (struct i2c_client *client,u8 reg,u8 value);
static inline int adv7171_read (struct i2c_client *client,u8 reg);
static int adv7171_write_block (struct i2c_client *client, const u8 *data,
                                unsigned int len);
static int adv7171_command (struct i2c_client *client,unsigned int cmd,
                                void * arg);
static char adv7171_name[] = "adv7171";

static char *norms[] = { "PAL", "NTSC" };

#define TR0MODE     0x00
#define TR0RST      0x80

static const unsigned char init_NTSC[] = {
        0x00, 0x00,             /* MR0				*/
        0x01, 0x58,             /* MR1				*/
        0x02, 0x00,             /* MR2 RTC control: bits 2 and 1*/
        0x03, 0x00,             /* MR3				*/
        0x04, 0x10,             /* MR4				*/
        0x05, 0x00,             /* Reserved			*/
        0x06, 0x00,             /* Reserved			*/
        0x07, 0x00,             /* TM0				*/
        0x08, 0x00,             /* TM1				*/
        0x09, 0x16,             /* Fsc0				*/
        0x0a, 0x7c,             /* Fsc1				*/
        0x0b, 0xf0,             /* Fsc2				*/
        0x0c, 0x21,             /* Fsc3				*/
        0x0d, 0x00,             /* Subcarrier Phase		*/
        0x0e, 0x00,             /* Closed Capt. Ext 0		*/
        0x0f, 0x00,             /* Closed Capt. Ext 1		*/
        0x10, 0x00,             /* Closed Capt. 0		*/
        0x11, 0x00,             /* Closed Capt. 1		*/
        0x12, 0x00,             /* Pedestal Ctl 0		*/
        0x13, 0x00,             /* Pedestal Ctl 1		*/
        0x14, 0x00,             /* Pedestal Ctl 2		*/
        0x15, 0x00,             /* Pedestal Ctl 3		*/
        0x16, 0x00,             /* CGMS_WSS_0			*/
        0x17, 0x00,             /* CGMS_WSS_1			*/
        0x18, 0x00,             /* CGMS_WSS_2			*/
        0x19, 0x00,             /* Teletext Ctl			*/
};

static const unsigned char init_PAL[] = {
        0x00, 0x05,             /* MR0				*/
        0x01, 0x00,             /* MR1				*/
        0x02, 0x00,             /* MR2 RTC control: bits 2 and 1*/
        0x03, 0x00,             /* MR3				*/
        0x04, 0x00,             /* MR4				*/
        0x05, 0x00,             /* Reserved			*/
        0x06, 0x00,             /* Reserved			*/
        0x07, 0x00,             /* TM0				*/
        0x08, 0x00,             /* TM1				*/
        0x09, 0xcb,             /* Fsc0				*/
        0x0a, 0x8a,             /* Fsc1				*/
        0x0b, 0x09,             /* Fsc2				*/
        0x0c, 0x2a,             /* Fsc3				*/
        0x0d, 0x00,             /* Subcarrier Phase		*/
        0x0e, 0x00,             /* Closed Capt. Ext 0		*/
        0x0f, 0x00,             /* Closed Capt. Ext 1		*/
        0x10, 0x00,             /* Closed Capt. 0		*/
        0x11, 0x00,             /* Closed Capt. 1		*/
        0x12, 0x00,             /* Pedestal Ctl 0		*/
        0x13, 0x00,             /* Pedestal Ctl 1		*/
        0x14, 0x00,             /* Pedestal Ctl 2		*/
        0x15, 0x00,             /* Pedestal Ctl 3		*/
        0x16, 0x00,             /* CGMS_WSS_0			*/
        0x17, 0x00,             /* CGMS_WSS_1			*/
        0x18, 0x00,             /* CGMS_WSS_2			*/
        0x19, 0x00,             /* Teletext Ctl			*/
};

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
	.left_margin	= 0,
	.right_margin	= 0,
	.upper_margin	= 0,
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

static int bfin_fb_mmap(struct fb_info *info, struct vm_area_struct * vma)
{
	/* we really dont need any map ... not sure how the smem_start will
	   end up in the kernel
	*/
	vma->vm_start  = (int)rgb_buffer;
	/*   VM_MAYSHARE limits for mprotect(), and must be set on nommu.
	 *   Other flags can be set, and are documented in
	 *   include/linux/mm.h
	 */
	vma->vm_flags |=  VM_MAYSHARE;
	return 0;
}

static void bfin_framebuffer_init(void *ycrcb_buffer)
{
	char *dest = (void *)ycrcb_buffer;
	int lines;

	for ( lines = 1; lines <= YCBCR_HEIGHT; lines++ ) {
		int offset = 0;
		unsigned int code;
		int i;
#ifdef CONFIG_NTSC
		if ((lines>=1 && lines<=3) || (lines>=266 && lines <=282))
			offset = 0;
		else if ((lines>=4 && lines<=19) || (lines>=264 && lines<=265))
			offset = 1;
		else if (lines>=20 && lines<=263)
			offset = 2;
		else if (lines>=283 && lines<=525)
			offset = 3;
#else /* CONFIG_PAL */
		if ((lines>=1 && lines<=22) || (lines>=311 && lines<=312))
			offset = 0;
		else if (lines>=23 && lines<=310)
			offset = 1;
		else if ((lines>=313 && lines<=335) || (lines>=624 && lines <=625))
			offset = 2;
		else if (lines>=336 && lines<=623)
			offset = 3;
#endif
		else
			printk(KERN_WARNING "Frame buffer init error\n");

		/* Output EAV code */
		code = system_code_map[ offset ].eav;
		*dest++ = (char) (code >> 24) & 0xff;
		*dest++ = (char) (code >> 16) & 0xff;
		*dest++ = (char) (code >> 8) & 0xff;
		*dest++ = (char) (code) & 0xff;

		/* Output horizontal blanking */
		for ( i = 0; i < HB_LENGTH/2; ++i ) {
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
		for ( i = 0; i <RGB_WIDTH; ++i ) {
			*dest++ = 0x80;
			*dest++ = 0x10;
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

	for (oddline = FIELD1_AV_START, evenline = FIELD2_AV_START, rgbline = 0;
	     oddline <= FIELD1_AV_END; oddline ++, evenline ++) {
		odd_yuv= (unsigned char *)((ycrcb_base + (oddline * YCBCR_WIDTH))+HB_LENGTH+8);
		rgb_ptr = (unsigned char *)(rgb_base + (rgbline++)*RGB_WIDTH*3);
		fb_memcpy((u32 *)rgb_l1,(u32 *)rgb_ptr,RGB_WIDTH*3/4);
		rgb2yuv(rgb_l1,yuv_l1,RGB_WIDTH);
		fb_memcpy((u32 *)odd_yuv, (u32 *)yuv_l1, RGB_WIDTH/2);

		even_yuv = (unsigned char *)((ycrcb_base + (evenline * YCBCR_WIDTH))+HB_LENGTH+8);
		rgb_ptr = (unsigned char *)(rgb_base + (rgbline++)*RGB_WIDTH*3);
		fb_memcpy((u32 *)rgb_l1,(u32 *)rgb_ptr,RGB_WIDTH*3/4);
		rgb2yuv(rgb_l1,yuv_l1,RGB_WIDTH);
		fb_memcpy((u32 *)even_yuv, (u32 *)yuv_l1, RGB_WIDTH/2);
	}
}

static void bfin_rgb_buffer_init(struct rgb_t *rgb_buffer, int width, int height)
{
	struct rgb_t *rgb_ptr = rgb_buffer;
	int i;
	/* the first block */
	for (i=0; i<width*height/4; i++) {
		rgb_ptr->r = 0xfe;
		rgb_ptr->g = 0x00;
		rgb_ptr->b = 0x00;
		rgb_ptr++;
	}
	/* the second block */
	for (; i<width*height/2; i++) {
		rgb_ptr->r = 0x00;
		rgb_ptr->g = 0xfe;
		rgb_ptr->b = 0x00;
		rgb_ptr++;
	}

	/* the third block */
	for (; i<width*height*3/4; i++) {
		rgb_ptr->r = 0x00;
		rgb_ptr->g = 0x00;
		rgb_ptr->b = 0xfe;
		rgb_ptr++;
	}

	/* the fourth block */
	for (; i<width*height; i++) {
		rgb_ptr->r = 0xfe;
		rgb_ptr->g = 0x00;
		rgb_ptr->b = 0xfe;
		rgb_ptr++;
	}
}

static void bfin_config_dma(void *ycrcb_buffer)
{
	bfin_write_DMA0_START_ADDR(ycrcb_buffer);
	bfin_write_DMA0_X_COUNT(YCBCR_WIDTH/2);
	bfin_write_DMA0_X_MODIFY(0x0002);
	bfin_write_DMA0_Y_COUNT(YCBCR_HEIGHT);
	bfin_write_DMA0_Y_MODIFY(0x0002);
	bfin_write_DMA0_CONFIG(0x1015);
}

static void bfin_disable_dma(void)
{
	bfin_write_DMA0_CONFIG(bfin_read_DMA0_CONFIG() & ~DMAEN);
}

void fb_memcpy(unsigned int * dest,unsigned int *src,size_t count)
{
	while (count--)
		*dest++ = *src++;
}

static void bfin_config_ppi(void)
{
#ifdef CONFIG_BF537
	bfin_write_PORTG_FER  (0xFFFF); /* PPI[15:0]    */
	bfin_write_PORTF_FER(bfin_read_PORTF_FER() | 0x8380); /* PF.15 - PPI_CLK */
	bfin_write_PORT_MUX(bfin_read_PORT_MUX() & ~0x0E00);
	bfin_write_PORT_MUX(bfin_read_PORT_MUX() | 0x0100);
#endif
	bfin_write_PPI_CONTROL(0x0082);
	bfin_write_PPI_FRAME  (YCBCR_HEIGHT);
}

static void bfin_enable_ppi(void)
{
	bfin_write_PPI_CONTROL(bfin_read_PPI_CONTROL() | PORT_EN);
}

static void bfin_disable_ppi(void)
{
	bfin_write_PPI_CONTROL(bfin_read_PPI_CONTROL() & ~PORT_EN);
}

static inline int
adv7171_write (struct i2c_client *client,
               u8                 reg,
               u8                 value)
{
	struct adv7171 *encoder = i2c_get_clientdata(client);

	encoder->reg[reg] = value;
	return i2c_smbus_write_byte_data(client, reg, value);
}

static inline int
adv7171_read (struct i2c_client *client,
              u8                 reg)
{
	return i2c_smbus_read_byte_data(client, reg);
}

static int
adv7171_write_block (struct i2c_client *client,
                     const u8          *data,
                     unsigned int       len)
{
	int ret = -1;
	u8 reg;

	while (len >= 2) {
		reg = *data++;
		if ((ret = adv7171_write(client, reg, *data++)) < 0)
			break;
		len -= 2;
	}
	return ret;
}

static int
adv7171_command (struct i2c_client *client,
                 unsigned int       cmd,
                 void *             arg)
{
	struct adv7171 *encoder = i2c_get_clientdata(client);

	switch (cmd) {

	case ENCODER_GET_CAPABILITIES:
	{
		struct video_encoder_capability *cap = arg;

		cap->flags = VIDEO_ENCODER_PAL |
		             VIDEO_ENCODER_NTSC;
		cap->inputs = 2;
		cap->outputs = 1;
	}
		break;

	case ENCODER_SET_NORM:
	{
		int iarg = *(int *) arg;

		printk(KERN_DEBUG "%s_command: set norm %d",
			I2C_NAME(client), iarg);

		switch (iarg) {

		case VIDEO_MODE_NTSC:
			adv7171_write_block(client, init_NTSC,
			                    sizeof(init_NTSC));
			if (encoder->input == 0)
				adv7171_write(client, 0x02, 0x0e);
			adv7171_write(client, 0x07, TR0MODE | TR0RST);
			adv7171_write(client, 0x07, TR0MODE);
			break;
		case VIDEO_MODE_PAL:
			adv7171_write_block(client, init_PAL,
			                    sizeof(init_PAL));
			if (encoder->input == 0)
				adv7171_write(client, 0x02, 0x0e);
			adv7171_write(client, 0x07, TR0MODE | TR0RST);
			adv7171_write(client, 0x07, TR0MODE);
			break;

		default:
			printk(KERN_ERR "%s: illegal norm: %d\n",
			       I2C_NAME(client), iarg);
			return -EINVAL;

		}
		printk(KERN_DEBUG "%s: switched to %s\n", I2C_NAME(client),
		       norms[iarg]);
		encoder->norm = iarg;
	}
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/*
 * Generic i2c probe
 * concerning the addresses: i2c wants 7 bit (without the r/w bit), so '>>1'
 */
static unsigned short normal_i2c[] = {
	I2C_ADV7171 >> 1,
	(I2C_ADV7171 >> 1) + 1,
	I2C_CLIENT_END
};

static unsigned short probe[2] = { I2C_CLIENT_END, I2C_CLIENT_END };
static unsigned short ignore[2] = { I2C_CLIENT_END, I2C_CLIENT_END };

static struct i2c_client_address_data addr_data = {
        .normal_i2c             = normal_i2c,
        .probe                  = probe,
        .ignore                 = ignore,
};

static struct i2c_driver i2c_driver_adv7171;

static int
adv7171_detect_client (struct i2c_adapter *adapter,
                       int                 address,
                       int                 kind)
{
	int i;
	struct i2c_client *client;
	struct adv7171 *encoder;
	char *dname;

	printk(KERN_INFO
	       "adv7171.c: detecting adv7171 client on address 0x%x\n",
	       address << 1);

	/* Check if the adapter supports the needed features */
	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE_DATA))
		return 0;

	client = kmalloc(sizeof(struct i2c_client), GFP_KERNEL);
	if (client == 0)
		return -ENOMEM;
	memset(client, 0, sizeof(struct i2c_client));
	client->addr = address;
	client->adapter = adapter;
	client->driver = &i2c_driver_adv7171;
	if ((client->addr == I2C_ADV7171 >> 1) ||
	    (client->addr == (I2C_ADV7171 >> 1) + 1)) {
		dname = adv7171_name;
	} else {
		/* We should never get here!!! */
		kfree(client);
		return 0;
	}
	strlcpy(I2C_NAME(client), dname, sizeof(I2C_NAME(client)));

	encoder = kmalloc(sizeof(struct adv7171), GFP_KERNEL);
	if (encoder == NULL) {
		kfree(client);
		return -ENOMEM;
	}
	memset(encoder, 0, sizeof(struct adv7171));
#ifdef CONFIG_NTSC
	encoder->norm = VIDEO_MODE_NTSC;
#else /* CONFIG_PAL */
	encoder->norm = VIDEO_MODE_PAL;
#endif
	encoder->input = 0;
	encoder->enable = 1;
	i2c_set_clientdata(client, encoder);

	i = i2c_attach_client(client);
	if (i) {
		kfree(client);
		kfree(encoder);
		return i;
	}
#ifdef CONFIG_NTSC
	i = adv7171_write_block(client, init_NTSC, sizeof(init_NTSC));
#else /* CONFIG_PAL */
	i = adv7171_write_block(client, init_PAL, sizeof(init_PAL));
#endif
	if (i >= 0) {
		i = adv7171_write(client, 0x07, TR0MODE | TR0RST);
		i = adv7171_write(client, 0x07, TR0MODE);
		i = adv7171_read(client, 0x12);
		printk(KERN_INFO "%s_attach: rev. %d at 0x%02x\n",
		       I2C_NAME(client), i & 1, client->addr << 1);

	}
	if (i < 0) {
		printk(KERN_ERR "%s_attach: init error 0x%x\n",
		       I2C_NAME(client), i);
	}
	return 0;
}

static int
adv7171_attach_adapter (struct i2c_adapter *adapter)
{
	printk(KERN_INFO
		"adv7171.c: starting probe for adapter %s (0x%x)\n",
		I2C_NAME(adapter), adapter->id);
	return i2c_probe(adapter, &addr_data, &adv7171_detect_client);
}

static int
adv7171_detach_client (struct i2c_client *client)
{
	struct adv7171 *encoder = i2c_get_clientdata(client);
	int err;

	err = i2c_detach_client(client);
	if (err) {
		return err;
	}
	kfree(encoder);
	kfree(client);

	return 0;
}

/* ----------------------------------------------------------------------- */

static struct i2c_driver i2c_driver_adv7171 = {
	.driver = {
		.name = "adv7171",      /* name */
	},

	.id = I2C_DRIVERID_ADV7170,
	.attach_adapter = adv7171_attach_adapter,
	.detach_client = adv7171_detach_client,
	.command = adv7171_command,
};

int __init bfin_ad7171_fb_init(void)
{
	int ret = 0;

	printk(KERN_NOTICE "bfin_ad7171_fb: initializing:\n");
	ycrcb_buffer = (struct ycrcb_t *)kmalloc(BFIN_FB_YCRCB_LEN, GFP_KERNEL);
	memset(ycrcb_buffer, 0, BFIN_FB_YCRCB_LEN);
	rgb_buffer = (struct rgb_t *)kmalloc(BFIN_FB_PHYS_LEN , GFP_KERNEL);
	memset(rgb_buffer, 0, BFIN_FB_PHYS_LEN);

	bfin_ad7171_fb.screen_base = (void *)rgb_buffer;
	bfin_ad7171_fb_fix.smem_start = (int)rgb_buffer;
	if (!bfin_ad7171_fb.screen_base) {
		printk(KERN_ERR "bfin_ad7171_fb: unable to map device\n");
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
	i2c_add_driver(&i2c_driver_adv7171);
	return ret;
}

static int bfin_ad7171_fb_open(struct fb_info *info, int user)
{
	rgb_l1 = (unsigned char *)l1_data_A_sram_alloc(RGB_WIDTH*3);
	if (!rgb_l1) {
		printk(KERN_ERR "alloc rgb l1 buffer failed\n");
		return -ENOMEM;
	}
	yuv_l1 = (unsigned char *)l1_data_A_sram_alloc(RGB_WIDTH*2);
	if (!yuv_l1) {
		printk(KERN_ERR "alloc YCbCr l1 buffer failed\n");
		return -ENOMEM;
	}

	bfin_ad7171_fb.screen_base = (void *)rgb_buffer;
	bfin_ad7171_fb_fix.smem_start = (int)rgb_buffer;
	if (!bfin_ad7171_fb.screen_base) {
		printk(KERN_ERR "bfin_ad7171_fb: unable to map device\n");
		return -ENOMEM;
	}

	bfin_framebuffer_init(ycrcb_buffer);
	bfin_rgb_buffer_init(rgb_buffer,RGB_WIDTH,RGB_HEIGHT);
	bfin_framebuffer_timer_setup();
	bfin_config_ppi();
	bfin_config_dma(ycrcb_buffer);
	bfin_enable_ppi();
	return 0;
}

static int bfin_ad7171_fb_release(struct fb_info *info, int user)
{
	if (rgb_l1)
		l1_data_A_sram_free(rgb_l1);
	if (yuv_l1)
		l1_data_A_sram_free(yuv_l1);
	del_timer(&bfin_framebuffer_timer);
	bfin_disable_dma();
	bfin_disable_ppi();
	return 0;
}

static int bfin_ad7171_fb_check_var(struct fb_var_screeninfo *var,
			     struct fb_info *info)
{
	printk(KERN_NOTICE "bfin_ad7171_fb Variables checked\n") ;
	return -EINVAL;
}

static int bfin_ad7171_fb_set_par(struct fb_info *info)
{
	printk(KERN_NOTICE "bfin_ad7171_fb_set_par called not implemented\n") ;
	return -EINVAL;
}


static int bfin_ad7171_fb_pan_display(struct fb_var_screeninfo *var,
			       struct fb_info *info)
{
	printk(KERN_NOTICE "bfin_ad7171_fb_pan_display called ... not implemented\n");
	return -EINVAL;
}

/* 0 unblank, 1 blank, 2 no vsync, 3 no hsync, 4 off */
static int bfin_ad7171_fb_blank(int blank, struct fb_info *info)
{
	printk(KERN_NOTICE "bfin_ad7171_fb_blank called ... not implemented\n");
	return -EINVAL;
}

static void bfin_ad7171_fb_fillrect(struct fb_info *info, const struct fb_fillrect *rect)
{
	printk(KERN_NOTICE "bfin_ad7171_fb_fillrect called ... not implemented\n");
}

static void bfin_ad7171_fb_imageblit(struct fb_info *info, const struct fb_image *image)
{
	printk(KERN_NOTICE "bfin_ad7171_fb_imageblit called ... not implemented\n");
}

static void __exit bfin_ad7171_fb_exit(void)
{
	if (ycrcb_buffer)
		kfree(ycrcb_buffer);
	if (rgb_buffer)
		kfree(rgb_buffer);
	unregister_framebuffer(&bfin_ad7171_fb);
	i2c_del_driver(&i2c_driver_adv7171);
}

MODULE_LICENSE("GPL");
module_init(bfin_ad7171_fb_init);
module_exit(bfin_ad7171_fb_exit);
