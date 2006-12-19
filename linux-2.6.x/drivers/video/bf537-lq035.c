/*
 * drivers/video/bfin-lq035.c
 * Analog Devices Blackfin(BF537 STAMP) + SHARP TFT LCD.
 *
 * For more information, please read the data sheet:
 * http://blackfin.uclinux.org/frs/download.php/829/LQ035q7db03.pdf
 *
 * This program is free software; you can distribute it and/or modify it
 * under the terms of the GNU General Public License (Version 2) as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
 *
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
#include <linux/timer.h>
#include <linux/device.h>
#include <linux/backlight.h>
#include <linux/lcd.h>
#include <linux/i2c.h>
#include <linux/dma-mapping.h>
#include <linux/platform_device.h>

#include <asm/mach/cdefBF537.h>
#include <asm/blackfin.h>
#include <asm/irq.h>
#include <asm/dpmc.h>
#include <asm/dma-mapping.h>
#include <asm/dma.h>

#define DRIVER_NAME "bf537-lq035"

#define NO_BL 1

#define MAX_BRIGHENESS 	95
#define MIN_BRIGHENESS  5

static unsigned char* fb_buffer;          /* RGB Buffer */
static dma_addr_t dma_handle;             /* ? */
static unsigned long* dma_desc_table;

#ifdef CONFIG_FB_BFIN_LANDSCAPE
static int landscape = 1;
#else
static int landscape = 0;
#endif

#ifdef CONFIG_FB_BFIN_BGR
static int bgr = 1;
#else
static int bgr = 0;
#endif

module_param(landscape, int, 0);
MODULE_PARM_DESC(landscape,
	"LANDSCAPE use 320x240 instead of Native 240x320 Resolution");

module_param(bgr, int, 0);
MODULE_PARM_DESC(bgr,
	"BGR use 16-bit BGR-565 instead of RGB-565");

static unsigned long current_brightness;  /* backlight */

/* AD5280 vcomm */
static unsigned char vcomm_value = 150;

#define	AD5280_DRV_NAME		"ad5280"
static struct i2c_driver ad5280_driver;
static struct i2c_client* ad5280_client;

static unsigned short ignore[] 		= { I2C_CLIENT_END };
static unsigned short normal_addr[] = { CONFIG_LQ035_SLAVE_ADDR>>1, I2C_CLIENT_END };

static struct i2c_client_address_data addr_data = {
	.normal_i2c			= normal_addr,
	.probe				= ignore,
	.ignore				= ignore,
};

static void set_vcomm(void)
{
	int nr;

	if (ad5280_client) {
		nr = i2c_smbus_write_byte_data(ad5280_client, 0x00, vcomm_value);
	}
}

static int ad5280_probe(struct i2c_adapter *adap, int addr, int kind)
{
	struct i2c_client *client;
	int rc;

	client = kmalloc(sizeof(struct i2c_client), GFP_KERNEL);
	if (!client)
		return -ENOMEM;

	memset(client, 0, sizeof(struct i2c_client));
	strncpy(client->name, AD5280_DRV_NAME, I2C_NAME_SIZE);
	client->addr = addr;
	client->adapter = adap;
	client->driver = &ad5280_driver;

	if ((rc = i2c_attach_client(client)) != 0) {
		kfree(client);
		printk(KERN_ERR DRIVER_NAME ": i2c_attach_client fail: %d\n", rc);
		return rc;
	}

	ad5280_client = client;
	set_vcomm();
	return 0;
}

static int ad5280_attach(struct i2c_adapter *adap)
{
	if (adap->algo->functionality)
		return i2c_probe(adap, &addr_data, ad5280_probe);
	else
		return ad5280_probe(adap, CONFIG_LQ035_SLAVE_ADDR>>1, 0);
}

static int ad5280_detach_client(struct i2c_client *client)
{
	int rc;
	if ((rc = i2c_detach_client(client)) == 0)
		kfree(i2c_get_clientdata(client));
	return rc;
}


static struct i2c_driver ad5280_driver = {
	.id              = 0x65,
	.attach_adapter  = ad5280_attach,
	.detach_client   = ad5280_detach_client,
};

#ifdef CONFIG_PNAV10
#define MOD     GPIO_PH13

#define bfin_write_TIMER_LP_CONFIG 	bfin_write_TIMER0_CONFIG
#define bfin_write_TIMER_LP_WIDTH 	bfin_write_TIMER0_WIDTH
#define bfin_write_TIMER_LP_PERIOD	bfin_write_TIMER0_PERIOD
#define bfin_read_TIMER_LP_COUNTER	bfin_read_TIMER0_COUNTER
#define TIMDIS_LP			TIMDIS0
#define TIMEN_LP			TIMEN0

#define bfin_write_TIMER_SPS_CONFIG 	bfin_write_TIMER1_CONFIG
#define bfin_write_TIMER_SPS_WIDTH 	bfin_write_TIMER1_WIDTH
#define bfin_write_TIMER_SPS_PERIOD	bfin_write_TIMER1_PERIOD
#define TIMDIS_SPS			TIMDIS1
#define TIMEN_SPS			TIMEN1

#define bfin_write_TIMER_SP_CONFIG 	bfin_write_TIMER5_CONFIG
#define bfin_write_TIMER_SP_WIDTH 	bfin_write_TIMER5_WIDTH
#define bfin_write_TIMER_SP_PERIOD	bfin_write_TIMER5_PERIOD
#define TIMDIS_SP			TIMDIS5
#define TIMEN_SP			TIMEN5

#define bfin_write_TIMER_PS_CLS_CONFIG 	bfin_write_TIMER2_CONFIG
#define bfin_write_TIMER_PS_CLS_WIDTH 	bfin_write_TIMER2_WIDTH
#define bfin_write_TIMER_PS_CLS_PERIOD	bfin_write_TIMER2_PERIOD
#define TIMDIS_PS_CLS			TIMDIS2
#define TIMEN_PS_CLS			TIMEN2

#define bfin_write_TIMER_REV_CONFIG 	bfin_write_TIMER3_CONFIG
#define bfin_write_TIMER_REV_WIDTH 	bfin_write_TIMER3_WIDTH
#define bfin_write_TIMER_REV_PERIOD	bfin_write_TIMER3_PERIOD
#define TIMDIS_REV			TIMDIS3
#define TIMEN_REV			TIMEN3
#define bfin_read_TIMER_REV_COUNTER	bfin_read_TIMER3_COUNTER

#define	FREQ_PPI_CLK         (5*1024*1024)  /* PPI_CLK 5MHz */

#else

#define UD      GPIO_PF13	/* Up / Down */
#define MOD     GPIO_PF10
#define LBR     GPIO_PF14	/* Left Right */

#define bfin_write_TIMER_LP_CONFIG 	bfin_write_TIMER6_CONFIG
#define bfin_write_TIMER_LP_WIDTH 	bfin_write_TIMER6_WIDTH
#define bfin_write_TIMER_LP_PERIOD	bfin_write_TIMER6_PERIOD
#define bfin_read_TIMER_LP_COUNTER	bfin_read_TIMER6_COUNTER
#define TIMDIS_LP			TIMDIS6
#define TIMEN_LP			TIMEN6

#define bfin_write_TIMER_SPS_CONFIG 	bfin_write_TIMER1_CONFIG
#define bfin_write_TIMER_SPS_WIDTH 	bfin_write_TIMER1_WIDTH
#define bfin_write_TIMER_SPS_PERIOD	bfin_write_TIMER1_PERIOD
#define TIMDIS_SPS			TIMDIS1
#define TIMEN_SPS			TIMEN1

#define bfin_write_TIMER_SP_CONFIG 	bfin_write_TIMER0_CONFIG
#define bfin_write_TIMER_SP_WIDTH 	bfin_write_TIMER0_WIDTH
#define bfin_write_TIMER_SP_PERIOD	bfin_write_TIMER0_PERIOD
#define TIMDIS_SP			TIMDIS0
#define TIMEN_SP			TIMEN0

#define bfin_write_TIMER_PS_CLS_CONFIG 	bfin_write_TIMER7_CONFIG
#define bfin_write_TIMER_PS_CLS_WIDTH 	bfin_write_TIMER7_WIDTH
#define bfin_write_TIMER_PS_CLS_PERIOD	bfin_write_TIMER7_PERIOD
#define TIMDIS_PS_CLS			TIMDIS7
#define TIMEN_PS_CLS			TIMEN7

#define bfin_write_TIMER_REV_CONFIG 	bfin_write_TIMER5_CONFIG
#define bfin_write_TIMER_REV_WIDTH 	bfin_write_TIMER5_WIDTH
#define bfin_write_TIMER_REV_PERIOD	bfin_write_TIMER5_PERIOD
#define TIMDIS_REV			TIMDIS5
#define TIMEN_REV			TIMEN5
#define bfin_read_TIMER_REV_COUNTER	bfin_read_TIMER5_COUNTER

#define	FREQ_PPI_CLK         (6*1000*1000)  /* PPI_CLK 6MHz */

#endif

#define LCD_X_RES			240 /*Horizontal Resolution */
#define LCD_Y_RES			320 /* Vertical Resolution */

#define LCD_BBP				16  /* Bit Per Pixel */

/* the LCD and the DMA start counting differently;
 * since one starts at 0 and the other starts at 1,
 * we have a difference of 1 between START_LINES
 * and U_LINES.
 */
#define START_LINES          8              /* lines for field flyback or field blanking signal */
#define U_LINES              (9)            /* number of undisplayed blanking lines */

#define FRAMES_PER_SEC       (60)

#define DCLKS_PER_FRAME      (FREQ_PPI_CLK/FRAMES_PER_SEC)
#define DCLKS_PER_LINE       (DCLKS_PER_FRAME/(LCD_Y_RES+U_LINES))

#define PPI_CONFIG_VALUE     (PORT_DIR|XFR_TYPE|DLEN_16|POLS)
#define PPI_DELAY_VALUE      (0)
#define TIMER_CONFIG         (PWM_OUT|PERIOD_CNT|TIN_SEL|CLK_SEL)

#define ACTIVE_VIDEO_MEM_OFFSET	(LCD_X_RES*START_LINES*(LCD_BBP/8)) /* Active Video Offset */
#define ACTIVE_VIDEO_MEM_SIZE	(LCD_Y_RES*LCD_X_RES*(LCD_BBP/8))

static void start_timers(void) /* CHECK with HW */
{
	unsigned long flags;

	local_irq_save(flags);

	bfin_write_TIMER_ENABLE(TIMEN_REV);
	__builtin_bfin_ssync();

	while (bfin_read_TIMER_REV_COUNTER() <= 11);
	bfin_write_TIMER_ENABLE(TIMEN_LP);
	__builtin_bfin_ssync();

	while (bfin_read_TIMER_LP_COUNTER() < 3);
	bfin_write_TIMER_ENABLE(TIMEN_SP|TIMEN_SPS|TIMEN_PS_CLS);
	__builtin_bfin_ssync();

	local_irq_restore(flags);
}

static void config_timers(void) /* CHECKME */
{
	/* Stop timers */
	bfin_write_TIMER_DISABLE(TIMDIS_SP|TIMDIS_SPS|TIMDIS_REV|TIMDIS_LP|TIMDIS_PS_CLS);
	__builtin_bfin_ssync();

	/* LP, timer 6 */
	bfin_write_TIMER_LP_CONFIG(TIMER_CONFIG|PULSE_HI);
	bfin_write_TIMER_LP_WIDTH (1);

	bfin_write_TIMER_LP_PERIOD(DCLKS_PER_LINE);
	__builtin_bfin_ssync();

	/* SPS, timer 1 */
	bfin_write_TIMER_SPS_CONFIG(TIMER_CONFIG|PULSE_HI);
	bfin_write_TIMER_SPS_WIDTH(DCLKS_PER_LINE*2);
	bfin_write_TIMER_SPS_PERIOD((DCLKS_PER_LINE * (LCD_Y_RES+U_LINES)));
	__builtin_bfin_ssync();

	/* SP, timer 0 */
	bfin_write_TIMER_SP_CONFIG(TIMER_CONFIG|PULSE_HI);
	bfin_write_TIMER_SP_WIDTH (1);
	bfin_write_TIMER_SP_PERIOD(DCLKS_PER_LINE);
	__builtin_bfin_ssync();

	/* PS & CLS, timer 7 */
	bfin_write_TIMER_PS_CLS_CONFIG(TIMER_CONFIG);
	bfin_write_TIMER_PS_CLS_WIDTH (LCD_X_RES + START_LINES);
	bfin_write_TIMER_PS_CLS_PERIOD(DCLKS_PER_LINE);

	__builtin_bfin_ssync();

#ifdef NO_BL
	/* REV, timer 5 */
	bfin_write_TIMER_REV_CONFIG(TIMER_CONFIG|PULSE_HI);

	bfin_write_TIMER_REV_WIDTH(DCLKS_PER_LINE);
	bfin_write_TIMER_REV_PERIOD(DCLKS_PER_LINE*2);

	__builtin_bfin_ssync();
#endif
}

static void config_ppi(void)
{
	bfin_write_PPI_DELAY(PPI_DELAY_VALUE);
	bfin_write_PPI_COUNT(LCD_X_RES-1);
	/* 0x10 -> PORT_CFG -> 2 or 3 frame syncs */
	bfin_write_PPI_CONTROL((PPI_CONFIG_VALUE|0x10) & (~POLS));
}

static int config_dma(void)
{
	u32 i;

	assert(fb_buffer);

	if(landscape) {

		for (i=0;i<U_LINES;i++)
		{
			//blanking lines point to first line of fb_buffer
			dma_desc_table[2*i] = (unsigned long)&dma_desc_table[2*i+2];
			dma_desc_table[2*i+1] = (unsigned long)fb_buffer;
		}

		for (i=U_LINES;i<U_LINES+LCD_Y_RES;i++)
		{
			// visible lines
			dma_desc_table[2*i] = (unsigned long)&dma_desc_table[2*i+2];
			dma_desc_table[2*i+1] = (unsigned long)fb_buffer + (LCD_Y_RES+U_LINES-1-i)*2;
		}

		//last descriptor points to first
		dma_desc_table[2*(LCD_Y_RES+U_LINES-1)] = (unsigned long)&dma_desc_table[0];

		set_dma_x_count(CH_PPI, LCD_X_RES);
		set_dma_x_modify(CH_PPI, LCD_Y_RES*(LCD_BBP/8));
		set_dma_y_count(CH_PPI, 0);
		set_dma_y_modify(CH_PPI, 0);
		set_dma_next_desc_addr(CH_PPI, (unsigned long)dma_desc_table[0]);
		set_dma_config(CH_PPI, DMAFLOW_LARGE | NDSIZE_4 | WDSIZE_16);

	} else {

		set_dma_config(CH_PPI, set_bfin_dma_config(DIR_READ,DMA_FLOW_AUTO,INTR_DISABLE,DIMENSION_2D,DATA_SIZE_16));
		set_dma_x_count(CH_PPI, LCD_X_RES);
		set_dma_x_modify(CH_PPI,LCD_BBP/8);
		set_dma_y_count(CH_PPI, LCD_Y_RES+U_LINES);
		set_dma_y_modify(CH_PPI, LCD_BBP/8);
		set_dma_start_addr(CH_PPI, ((unsigned long) fb_buffer));
	}

	return 0;
}

static void init_ports(void)
{
	/*
		UD:      PF13
		MOD:     PF10
		LBR:     PF14
		PPI_CLK: PF15
	*/


#if (defined(UD) &&  defined(LBR))
	if (gpio_request(UD, NULL))
		printk(KERN_ERR"Requesting GPIO %d faild\n",UD);

	if (gpio_request(LBR, NULL))
		printk(KERN_ERR"Requesting GPIO %d faild\n",LBR);

	gpio_direction_output(UD);
	gpio_direction_output(LBR);

	gpio_set_value(UD,0);
	gpio_set_value(LBR,1);
#endif

	if (gpio_request(MOD, NULL))
		printk(KERN_ERR"Requesting GPIO %d faild\n",MOD);

	gpio_direction_output(MOD);
	gpio_set_value(MOD,1);

#ifdef CONFIG_PNAV10
	bfin_write_PORTF_FER(bfin_read_PORTF_FER() | (1U<<15)|(1U<<8)|(1U<<9)|(1U<<4)|(1U<<6)|(1U<<7));

	/* Enable PPI Data, TMR2, TMR5 */
	bfin_write_PORT_MUX(bfin_read_PORT_MUX() & ~(PGTE_SPORT|PGRE_SPORT|PGSE_SPORT|PFFE_PPI|PFS6E_SPI|PFS4E_SPI|PFFE|PFS4E));
#else
	bfin_write_PORTF_FER(bfin_read_PORTF_FER() | (1U<<15)|(1U<<8)|(1U<<9)|(1U<<4)|(1U<<2)|(1U<<3));

	/* Enable PPI Data, TMR2, TMR5 */
	bfin_write_PORT_MUX(bfin_read_PORT_MUX() & ~(PGTE_SPORT|PGRE_SPORT|PGSE_SPORT|PFFE_PPI|PFS6E_SPI|PFS4E_SPI));
	/* Enable TMR6 TMR7 */
	bfin_write_PORT_MUX(bfin_read_PORT_MUX() | PFTE_TIMER);
#endif

	bfin_write_PORTG_FER(bfin_read_PORTG_FER() | 0xFFFF);
	__builtin_bfin_ssync();
}

static struct fb_info bfin_lq035_fb;

static struct fb_var_screeninfo bfin_lq035_fb_defined = {
	.bits_per_pixel		= LCD_BBP,
	.activate		= FB_ACTIVATE_TEST,
	.xres			= LCD_X_RES,	/*default portrait mode RGB*/
	.yres			= LCD_Y_RES,
	.xres_virtual		= LCD_X_RES,
	.yres_virtual		= LCD_Y_RES,
	.height			= -1,
	.width			= -1,
	.left_margin 		= 0,
	.right_margin 		= 0,
	.upper_margin 		= 0,
	.lower_margin 		= 0,
	.red 			= {11, 5, 0},
	.green			= {5, 6, 0},
	.blue 			= {0, 5, 0},
	.transp 		= {0, 0, 0},
};

static struct fb_fix_screeninfo bfin_lq035_fb_fix __initdata = {
	.id 		= DRIVER_NAME,
	.smem_len 	= ACTIVE_VIDEO_MEM_SIZE,
	.type		= FB_TYPE_PACKED_PIXELS,
	.visual		= FB_VISUAL_TRUECOLOR,
	.xpanstep	= 0,
	.ypanstep	= 0,
	.line_length	= LCD_X_RES*(LCD_BBP/8),
	.accel		= FB_ACCEL_NONE,
};


static int bfin_lq035_fb_open(struct fb_info* info, int user)
{
	bfin_write_PPI_CONTROL(0);
	__builtin_bfin_ssync();

	set_vcomm();
	config_dma();
	config_ppi();

	/* start dma */
	enable_dma(CH_PPI);
	__builtin_bfin_ssync();
	bfin_write_PPI_CONTROL(bfin_read_PPI_CONTROL() | PORT_EN);
	__builtin_bfin_ssync();

	config_timers();
	start_timers();
//	gpio_set_value(MOD,1);

	return 0;
}

static int bfin_lq035_fb_release(struct fb_info* info, int user)
{

	bfin_write_TIMER_ENABLE(0);
	__builtin_bfin_ssync();

	bfin_write_PPI_CONTROL(0);
	__builtin_bfin_ssync();

	disable_dma(CH_PPI);

	return 0;
}


static int bfin_lq035_fb_check_var(struct fb_var_screeninfo *var, struct fb_info *info)
{

	if (var->bits_per_pixel != 16) {
		pr_debug("%s: depth not supported: %u BPP\n", __FUNCTION__,
			 var->bits_per_pixel);
		return -EINVAL;
	}

	if (info->var.xres != var->xres || info->var.yres != var->yres ||
	    info->var.xres_virtual != var->xres_virtual ||
	    info->var.yres_virtual != var->yres_virtual) {
		pr_debug("%s: Resolution not supported: X%u x Y%u \n",
			 __FUNCTION__, var->xres, var->yres);
		return -EINVAL;
	}

	/*
	 *  Memory limit
	 */

	if ((info->fix.line_length * var->yres_virtual) > info->fix.smem_len) {
		pr_debug("%s: Memory Limit requested yres_virtual = %u\n",
			 __FUNCTION__, var->yres_virtual);
		return -ENOMEM;
	}

	return 0;
}

/* fb_rotate
 * Rotate the display of this angle. This doesn't seems to be used by the core,
 * but as our hardware supports it, so why not implementing it...
 */
void bfin_lq035_fb_rotate(struct fb_info *fbi, int angle)
{

	pr_debug("%s: %p %d",__FUNCTION__, fbi, angle);
#if (defined(UD) &&  defined(LBR))
	switch (angle) {

	case 180:
		gpio_set_value(LBR,0);
		gpio_set_value(UD,1);
		break;
	default:
		gpio_set_value(LBR,1);
		gpio_set_value(UD,0);
		break;
	}
#endif
}

static int direct_mmap(struct fb_info *info, struct vm_area_struct * vma)
{
	if(landscape) {
		vma->vm_start = (unsigned long)fb_buffer;
	} else {
		vma->vm_start = (unsigned long) (fb_buffer + ACTIVE_VIDEO_MEM_OFFSET);
	}

	vma->vm_end = vma->vm_start + ACTIVE_VIDEO_MEM_SIZE;
	/* For those who don't understand how mmap works, go read
	 *   Documentation/nommu-mmap.txt.
	 * For those that do, you will know that the VM_MAYSHARE flag
	 * must be set in the vma->vm_flags structure on noMMU
	 *   Other flags can be set, and are documented in
	 *   include/linux/mm.h
	 */
	vma->vm_flags |=  VM_MAYSHARE;
	return 0 ;
}

static struct fb_ops bfin_lq035_fb_ops = {
	.owner 			= THIS_MODULE,
	.fb_open		= bfin_lq035_fb_open,
	.fb_release		= bfin_lq035_fb_release,
	.fb_check_var		= bfin_lq035_fb_check_var,
	.fb_rotate		= bfin_lq035_fb_rotate,
	.fb_mmap		= direct_mmap,
};

static int bl_get_brightness(struct backlight_device *bd)
{
	return current_brightness;;
}

static struct backlight_properties bfin_lq035fb_bl = {
	.owner			= THIS_MODULE,
	.max_brightness	= MAX_BRIGHENESS,
	.get_brightness	= bl_get_brightness,
};


static int lcd_get_power(struct lcd_device* dev)
{
	return 0;
}

static int lcd_set_power(struct lcd_device* dev, int power)
{
	return 0;
}

static int lcd_get_contrast(struct lcd_device* dev)
{
	return (int)vcomm_value;
}

static int lcd_set_contrast(struct lcd_device* dev, int contrast)
{
	if (contrast > 255)
		contrast = 255;
	if (contrast < 0)
		contrast = 0;

	vcomm_value = (unsigned char)contrast;
	set_vcomm();
	return 0;
}

static int lcd_check_fb(struct fb_info* fi)
{
	if (!fi || (fi == &bfin_lq035_fb))
		return 1;
	return 0;
}

static struct lcd_properties lcd = {
	.owner			= THIS_MODULE,
	.get_power		= lcd_get_power,
	.set_power		= lcd_set_power,
	.max_contrast   = 255,
	.get_contrast   = lcd_get_contrast,
	.set_contrast   = lcd_set_contrast,
	.check_fb		= lcd_check_fb,
};

static int __init bfin_lq035_fb_init(void)
{
	printk(KERN_INFO DRIVER_NAME ": FrameBuffer initializing...\n");

	if (request_dma(CH_PPI, "BF533_PPI_DMA") < 0)
		return -EFAULT;

	fb_buffer = dma_alloc_coherent(NULL, (LCD_Y_RES+U_LINES)*LCD_X_RES*(LCD_BBP/8), &dma_handle, GFP_KERNEL);

	if (NULL == fb_buffer) {
		printk(KERN_ERR DRIVER_NAME ": couldn't allocate dma buffer.\n");
		return -ENOMEM;
	}


#if L1_DATA_A_LENGTH != 0
	dma_desc_table = (unsigned long*)l1_data_A_sram_alloc(sizeof(unsigned long) * 2 * (LCD_Y_RES + U_LINES));
#else
	dma_desc_table = dma_alloc_coherent(NULL,sizeof(unsigned long) * 2 * (LCD_Y_RES + U_LINES), &dma_handle, 0);
#endif

	if (NULL == dma_desc_table) {
		printk(KERN_ERR DRIVER_NAME ": couldn't allocate dma descriptor.\n");
		dma_free_coherent(NULL, (LCD_Y_RES+U_LINES)*LCD_X_RES*(LCD_BBP/8), fb_buffer, dma_handle);
		return -ENOMEM;
	}


	memset(fb_buffer, 0xff, (LCD_Y_RES+U_LINES)*LCD_X_RES*(LCD_BBP/8));

	if(landscape) {
		bfin_lq035_fb_defined.xres			= LCD_Y_RES;
		bfin_lq035_fb_defined.yres			= LCD_X_RES;
		bfin_lq035_fb_defined.xres_virtual		= LCD_Y_RES;
		bfin_lq035_fb_defined.yres_virtual		= LCD_X_RES;

		bfin_lq035_fb_fix.line_length	= LCD_Y_RES*(LCD_BBP/8);

		bfin_lq035_fb.screen_base = (void*)fb_buffer;
		bfin_lq035_fb_fix.smem_start = (int)fb_buffer;

	} else {

		bfin_lq035_fb.screen_base = (void*)fb_buffer + ACTIVE_VIDEO_MEM_OFFSET;
		bfin_lq035_fb_fix.smem_start = (int)fb_buffer + ACTIVE_VIDEO_MEM_OFFSET;
	}

	if(bgr) {
		bfin_lq035_fb_defined.red.offset 		= 0;
		bfin_lq035_fb_defined.red.length 		= 5;
		bfin_lq035_fb_defined.red.msb_right 		= 0;

		bfin_lq035_fb_defined.green.offset 		= 5;
		bfin_lq035_fb_defined.green.length 		= 6;
		bfin_lq035_fb_defined.green.msb_right 		= 0;

		bfin_lq035_fb_defined.blue.offset 		= 11;
		bfin_lq035_fb_defined.blue.length 		= 5;
		bfin_lq035_fb_defined.blue.msb_right 		= 0;
	}

	bfin_lq035_fb.fbops = &bfin_lq035_fb_ops;
	bfin_lq035_fb.var = bfin_lq035_fb_defined;

	bfin_lq035_fb.fix = bfin_lq035_fb_fix;
	bfin_lq035_fb.flags = FBINFO_DEFAULT;

	if (register_framebuffer(&bfin_lq035_fb) < 0) {
		printk(KERN_ERR DRIVER_NAME ": unable to register framebuffer.\n");

		dma_free_coherent(NULL, (LCD_Y_RES+U_LINES)*LCD_X_RES*(LCD_BBP/8), fb_buffer, dma_handle);
		fb_buffer = NULL;
		return -EINVAL;
	}

	i2c_add_driver(&ad5280_driver);

	backlight_device_register("bf537-bl", NULL, &bfin_lq035fb_bl);
	lcd_device_register(DRIVER_NAME, NULL, &lcd);

	init_ports();

	return 0;
}

static void __exit bfin_lq035_fb_exit(void)
{
	if (fb_buffer != NULL)
		dma_free_coherent(NULL, (LCD_Y_RES+U_LINES)*LCD_X_RES*(LCD_BBP/8), fb_buffer, dma_handle);


#if L1_DATA_A_LENGTH != 0
	if (dma_desc_table) l1_data_A_sram_free(dma_desc_table);
#else
	if (dma_desc_table) dma_free_coherent(NULL,sizeof(unsigned long) * 2 * (LCD_Y_RES + U_LINES), &dma_handle, 0);
#endif

	free_dma(CH_PPI);

	unregister_framebuffer(&bfin_lq035_fb);
	i2c_del_driver(&ad5280_driver);

#if (defined(UD) &&  defined(LBR))
	gpio_free(LBR);
	gpio_free(UD);
#endif

	gpio_free(MOD);

	printk(KERN_INFO DRIVER_NAME ": Unregister LCD driver.\n");
}

MODULE_DESCRIPTION("SHARP LQ035Q7DB03 TFT LCD Driver");
MODULE_LICENSE("GPL");

module_init(bfin_lq035_fb_init);
module_exit(bfin_lq035_fb_exit);
