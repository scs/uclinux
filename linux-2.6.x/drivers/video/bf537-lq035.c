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

static unsigned long current_brightness;  /* backlight */

static void set_backlight(unsigned long val)
{
#ifndef NO_BL
	unsigned long timer_freq, timer_val;
	if (val < MIN_BRIGHENESS)
		val = MIN_BRIGHENESS;
	if (val > MAX_BRIGHENESS)
		val = MAX_BRIGHENESS;

	current_brightness = val;
	timer_freq = val * 500/100;

	bfin_write_TIMER_DISABLE(TIMDIS1);
	__builtin_bfin_ssync();

	timer_val = get_sclk() / timer_freq;
	bfin_write_TIMER1_PERIOD(timer_val);
	bfin_write_TIMER1_WIDTH (timer_val >> 1);
	bfin_write_TIMER1_CONFIG(PWM_OUT|PULSE_HI|PERIOD_CNT);
	bfin_write_TIMER_ENABLE(TIMEN1);
	__builtin_bfin_ssync();
#endif
}

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


#define START_LINES          8              /* lines for field flyback or field blanking signal */
#define U_LINES              (9)            /* number of undisplayed lines */

#define FRAMES_PER_SEC       (60)
#define	FREQ_PPI_CLK         (6*1024*1024)  /* PPI_CLK */
#define DCLKS_PER_FRAME      (FREQ_PPI_CLK/FRAMES_PER_SEC)
#define DCLKS_PER_LINE       (DCLKS_PER_FRAME/(320+U_LINES))

#define PPI_CONFIG_VALUE     (PORT_DIR|XFR_TYPE|DLEN_16|POLS)
#define PPI_DELAY_VALUE      (0)
#define TIMER_CONFIG         (PWM_OUT|PERIOD_CNT|TIN_SEL|CLK_SEL)

static void start_timers(void) /* CHECK with HW */
{
	unsigned long flags;

	local_irq_save(flags);

	bfin_write_TIMER_ENABLE(TIMEN5);
	__builtin_bfin_ssync();

	while (bfin_read_TIMER5_COUNTER() <= 11)
		;
	bfin_write_TIMER_ENABLE(TIMEN6);
	__builtin_bfin_ssync();

	while (bfin_read_TIMER6_COUNTER() < 3)
		;
	bfin_write_TIMER_ENABLE(TIMEN0|TIMEN1|TIMEN7);
	__builtin_bfin_ssync();

	local_irq_restore(flags);
}

static void config_timers(void) /* CHECKME */
{
	/* Stop timers */
	bfin_write_TIMER_DISABLE(TIMDIS0|TIMDIS1|TIMDIS5|TIMDIS6|TIMDIS7);
	__builtin_bfin_ssync();

	/* LP, timer 6 */
	bfin_write_TIMER6_CONFIG(TIMER_CONFIG|PULSE_HI);
	bfin_write_TIMER6_WIDTH (1);

	bfin_write_TIMER6_PERIOD(DCLKS_PER_LINE);
	__builtin_bfin_ssync();

	/* SPS, timer 1 */
	bfin_write_TIMER1_CONFIG(TIMER_CONFIG|PULSE_HI);
	bfin_write_TIMER1_WIDTH(DCLKS_PER_LINE*2);
	bfin_write_TIMER1_PERIOD((DCLKS_PER_LINE * (320+U_LINES)));
	__builtin_bfin_ssync();

	/* SP, timer 0 */
	bfin_write_TIMER0_CONFIG(TIMER_CONFIG|PULSE_HI);
	bfin_write_TIMER0_WIDTH (1);
	bfin_write_TIMER0_PERIOD(DCLKS_PER_LINE);
	__builtin_bfin_ssync();

	/* PS & CLS, timer 7 */
	bfin_write_TIMER7_CONFIG(TIMER_CONFIG);
	bfin_write_TIMER7_WIDTH (248);
	bfin_write_TIMER7_PERIOD(DCLKS_PER_LINE);

	__builtin_bfin_ssync();

#ifdef NO_BL
	/* REV, timer 5 */
	bfin_write_TIMER5_CONFIG(TIMER_CONFIG|PULSE_HI);

	bfin_write_TIMER5_WIDTH(DCLKS_PER_LINE);
	bfin_write_TIMER5_PERIOD(DCLKS_PER_LINE*2);

	__builtin_bfin_ssync();
#endif
}

static void config_ppi(void)
{
	bfin_write_PPI_DELAY(PPI_DELAY_VALUE);
	bfin_write_PPI_COUNT(240-1);
	/* 0x10 -> PORT_CFG -> 2 or 3 frame syncs */
	bfin_write_PPI_CONTROL((PPI_CONFIG_VALUE|0x10) & (~POLS));
}

static int config_dma(void)
{
	assert(fb_buffer);

	if (request_dma(CH_PPI, "BF533_PPI_DMA") < 0)
		return -EFAULT;

	set_dma_config(CH_PPI, set_bfin_dma_config(DIR_READ,DMA_FLOW_AUTO,INTR_DISABLE,DIMENSION_2D,DATA_SIZE_16));

	set_dma_x_count(CH_PPI, 240);
	set_dma_x_modify(CH_PPI, 2);

	set_dma_y_count(CH_PPI, 320+U_LINES);
	set_dma_y_modify(CH_PPI, 2);
	set_dma_start_addr(CH_PPI, ((unsigned long) fb_buffer));

	return 0;
}

static void init_ports(void)
{
	/*
		LCDPWR:  PF11
		?REV:    PF12
		UD:      PF13
		MOD:     PF10
		LBR:     PF14
		PPI_CLK: PF15
	*/

	bfin_write_PORTFIO_DIR(bfin_read_PORTFIO_DIR() | (1U<<11)|(1U<<13)|(1U<<10)|(1U<<14) |(1U<<6));
	bfin_write_PORTFIO_DIR(bfin_read_PORTFIO_DIR() & ~(1U<<15));

	bfin_write_PORTF_FER(bfin_read_PORTF_FER() | (1U<<15)|(1U<<8)|(1U<<9)|(1U<<7)|(1U<<4)|(1U<<2)|(1U<<3)|(1U<<6));
	bfin_write_PORTF_FER(bfin_read_PORTF_FER() & ~((1U<<14)|(1U<<10)|(1U<<13)|(1U<<11)));

	// bfin_write_PORTFIO_CLEAR((1U<<11));
	bfin_write_PORTFIO_SET((1U<<14)|(1U<<11));
	bfin_write_PORTFIO_CLEAR((1U<<10)| (1U<<13));

	bfin_write_PORTFIO_INEN(bfin_read_PORTFIO_INEN() | (1U<<15));

	/* Enable PPI Data, TMR2, TMR5 */
	bfin_write_PORT_MUX(bfin_read_PORT_MUX() & ~(PGTE_SPORT|PGRE_SPORT|PGSE_SPORT|PFFE_PPI|PFS6E_SPI|PFS4E_SPI));
	/* Enable TMR6 TMR7 */
	bfin_write_PORT_MUX(bfin_read_PORT_MUX() | PFTE_TIMER);

	bfin_write_PORTG_FER(bfin_read_PORTG_FER() | 0xFFFF);
	__builtin_bfin_ssync();
}

static struct fb_info bfin_lq035_fb;

static struct fb_var_screeninfo bfin_lq035_fb_defined = {
	.xres			= 240,
	.yres			= 320,
	.xres_virtual	= 240,
	.yres_virtual	= 320,
	.bits_per_pixel	= 16,
	.activate		= FB_ACTIVATE_TEST,
	.height			= -1,
	.width			= -1,

	.red			= {11,5, 0},
	.green			= {6, 5, 0},
	.blue			= {5, 0, 0},
	.transp			= {0, 0, 0},
};

static struct fb_fix_screeninfo bfin_lq035_fb_fix __initdata = {
	.id 		= DRIVER_NAME,
	.smem_len 	= 320*240*2,
	.type		= FB_TYPE_PACKED_PIXELS,
	.visual		= FB_VISUAL_TRUECOLOR,
	.xpanstep	= 0,
	.ypanstep	= 0,
	.line_length	= 240*2,
	.accel		= FB_ACCEL_NONE,
};

static int bfin_lq035_fb_open(struct fb_info* info, int user)
{
	bfin_write_PPI_CONTROL(0);
	__builtin_bfin_ssync();

	init_ports();
	//set_backlight(60);

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
	bfin_write_PORTFIO_SET((1U<<10));
	__builtin_bfin_ssync();

	return 0;
}

static int bfin_lq035_fb_release(struct fb_info* info, int user)
{
	bfin_write_TIMER_ENABLE(0);
	__builtin_bfin_ssync();

	bfin_write_PPI_CONTROL(0);
	__builtin_bfin_ssync();

	free_dma(CH_PPI);

	return 0;
}

static int bfin_lq035_fb_check_var(struct fb_var_screeninfo *var, struct fb_info *info)
{
	return -EINVAL;
}

static int direct_mmap(struct fb_info *info, struct vm_area_struct * vma)
{
	vma->vm_start = (unsigned long) (fb_buffer + 240*2*START_LINES);
	vma->vm_end = vma->vm_start + 320*240*2;
	/*   VM_MAYSHARE limits for mprotect(), and must be set on nommu.
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
	.fb_check_var	= bfin_lq035_fb_check_var,
	.fb_mmap		= direct_mmap,
};


static int bl_set_power(struct backlight_device *bd, int state)
{
	return 0;
}

static int bl_get_power(struct backlight_device *bd)
{
	return 0;
}

static int bl_set_brightness(struct backlight_device *bd, int intensity)
{
	set_backlight(intensity);
	return 0;
}

static int bl_get_brightness(struct backlight_device *bd)
{
	return current_brightness;;
}

static struct backlight_properties bfin_lq035fb_bl = {
	.owner			= THIS_MODULE,
	.get_power		= bl_get_power,
	.set_power		= bl_set_power,
	.max_brightness	= MAX_BRIGHENESS,
	.get_brightness	= bl_get_brightness,
	.set_brightness	= bl_set_brightness,
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

	fb_buffer = dma_alloc_coherent(NULL, (320+U_LINES)*240*2, &dma_handle, GFP_KERNEL);

	if (NULL == fb_buffer) {
		printk(KERN_ERR DRIVER_NAME ": couldn't allocate dma buffer.\n");
		return -ENOMEM;
	}

	memset(fb_buffer, 0xff, (320+U_LINES)*240*2);

	bfin_lq035_fb.screen_base = (void*)fb_buffer;
	bfin_lq035_fb_fix.smem_start = (int)fb_buffer;

	bfin_lq035_fb.fbops = &bfin_lq035_fb_ops;
	bfin_lq035_fb.var = bfin_lq035_fb_defined;

	bfin_lq035_fb.fix = bfin_lq035_fb_fix;
	bfin_lq035_fb.flags = FBINFO_DEFAULT;

	if (register_framebuffer(&bfin_lq035_fb) < 0) {
		printk(KERN_ERR DRIVER_NAME ": unable to register framebuffer.\n");

		dma_free_coherent(NULL, (320+U_LINES)*240*2, fb_buffer, dma_handle);
		fb_buffer = NULL;
		return -EINVAL;
	}

	i2c_add_driver(&ad5280_driver);

	backlight_device_register("bf537-bl", NULL, &bfin_lq035fb_bl);
	lcd_device_register(DRIVER_NAME, NULL, &lcd);

	return 0;
}

static void __exit bfin_lq035_fb_exit(void)
{
	if (fb_buffer != NULL)
		dma_free_coherent(NULL, (320+U_LINES)*240*2, fb_buffer, dma_handle);
	unregister_framebuffer(&bfin_lq035_fb);
	i2c_del_driver(&ad5280_driver);
	printk(KERN_INFO DRIVER_NAME ": Unregister LCD driver.\n");
}

MODULE_DESCRIPTION("SHARP LQ035Q7DB03 TFT LCD Driver");
MODULE_LICENSE("GPL");

module_init(bfin_lq035_fb_init);
module_exit(bfin_lq035_fb_exit);
