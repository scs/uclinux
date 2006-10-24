/*
 * File:         drivers/video/bfin_adv7393fb.c
 * Based on:     drivers/video/vga16fb.c
 * Author:       Michael Hennerich
 *
 * Created:      May. 24th 2006
 * Description:  Frame buffer driver for ADV7393/2 video encoder
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright 2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see the file COPYING, or write
 * to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/*
 * TODO: Remove Globals
 * TODO: Code Cleanup
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
#include <asm/uaccess.h>

#include <linux/dma-mapping.h>
#include <linux/proc_fs.h>

#include <linux/i2c.h>
#include <linux/i2c-dev.h>

#include "bfin_adv7393fb.h"

static struct adv7393fb_device *drv;
static int mode = VMODE;
static int mem = VMEM;

/*
 * I2C driver
 */

static char adv7393_name[] = "adv7393";

/*
 * card parameters
 */

static struct bfin_adv7393_fb_par {
	/* structure holding blackfin / adv7393 paramters when
	   screen is blanked */
	struct {
		u8 Mode;	/* ntsc/pal/? */
	} vga_state;
	atomic_t ref_count;
} bfin_par;

/* --------------------------------------------------------------------- */

static struct fb_var_screeninfo bfin_adv7393_fb_defined = {
	.xres = 720,
	.yres = 480,
	.xres_virtual = 720,
	.yres_virtual = 480,
	.bits_per_pixel = 16,
	.activate = FB_ACTIVATE_TEST,
	.height = -1,
	.width = -1,
	.left_margin = 0,
	.right_margin = 0,
	.upper_margin = 0,
	.lower_margin = 0,
	.vmode = FB_VMODE_INTERLACED,
	.red = {11, 5, 0},
	.green = {5, 6, 0},
	.blue = {0, 5, 0},
	.transp = {0, 0, 0},
};

static struct fb_fix_screeninfo bfin_adv7393_fb_fix __initdata = {
	.id = "BFIN ADV7393",
	.smem_len = 720 * 480 * 2,
	.type = FB_TYPE_PACKED_PIXELS,
	.visual = FB_VISUAL_TRUECOLOR,
	.xpanstep = 0,
	.ypanstep = 0,
	.line_length = 720 * 2,
	.accel = FB_ACCEL_NONE
};

static struct fb_ops bfin_adv7393_fb_ops = {
	.owner = THIS_MODULE,
	.fb_open = bfin_adv7393_fb_open,
	.fb_release = bfin_adv7393_fb_release,
	.fb_check_var = bfin_adv7393_fb_check_var,
	.fb_set_par = bfin_adv7393_fb_set_par,
	.fb_pan_display = bfin_adv7393_fb_pan_display,
	.fb_blank = bfin_adv7393_fb_blank,
	.fb_fillrect = bfin_adv7393_fb_fillrect,
	.fb_imageblit = bfin_adv7393_fb_imageblit,
	.fb_mmap = bfin_fb_mmap,
};

static int dma_desc_list(struct adv7393fb_device *fbdev, u16 arg)
{
	if (arg == BUILD) {	/* Build */
		fbdev->vb1 = l1_data_A_sram_alloc(sizeof(struct dmasg_t));
		if (fbdev->vb1 == NULL)
			goto error;
		else
			memset(fbdev->vb1, 0, sizeof(struct dmasg_t));

		fbdev->av1 = l1_data_A_sram_alloc(sizeof(struct dmasg_t));
		if (fbdev->av1 == NULL)
			goto error;
		else
			memset(fbdev->av1, 0, sizeof(struct dmasg_t));

		fbdev->vb2 = l1_data_A_sram_alloc(sizeof(struct dmasg_t));
		if (fbdev->vb2 == NULL)
			goto error;
		else
			memset(fbdev->vb2, 0, sizeof(struct dmasg_t));

		fbdev->av2 = l1_data_A_sram_alloc(sizeof(struct dmasg_t));
		if (fbdev->av2 == NULL)
			goto error;
		else
			memset(fbdev->av2, 0, sizeof(struct dmasg_t));

		/* Build linked DMA descriptor list */
		fbdev->vb1->next_desc_addr = (unsigned long)fbdev->av1;
		fbdev->av1->next_desc_addr = (unsigned long)fbdev->vb2;
		fbdev->vb2->next_desc_addr = (unsigned long)fbdev->av2;
		fbdev->av2->next_desc_addr = (unsigned long)fbdev->vb1;

		/* Save list head */
		fbdev->descriptor_list_head = fbdev->av2;

		/* Vertical Blanking Field 1 */
		fbdev->vb1->start_addr = VB_DUMMY_MEMORY_SOURCE;
		fbdev->vb1->cfg = DMA_CFG_VAL;

		fbdev->vb1->x_count =
		    fbdev->modes[mode].xres + fbdev->modes[mode].boeft_blank;

		fbdev->vb1->x_modify = 0;
		fbdev->vb1->y_count = fbdev->modes[mode].vb1_lines;
		fbdev->vb1->y_modify = 0;

		/* Active Video Field 1 */

		fbdev->av1->start_addr = (unsigned long)fbdev->fb_mem;
		fbdev->av1->cfg = DMA_CFG_VAL;
		fbdev->av1->x_count =
		    fbdev->modes[mode].xres + fbdev->modes[mode].boeft_blank;
		fbdev->av1->x_modify = fbdev->modes[mode].bpp / 8;
		fbdev->av1->y_count = fbdev->modes[mode].a_lines;
		fbdev->av1->y_modify =
		    (fbdev->modes[mode].xres - fbdev->modes[mode].boeft_blank +
		     1) * (fbdev->modes[mode].bpp / 8);

		/* Vertical Blanking Field 2 */

		fbdev->vb2->start_addr = VB_DUMMY_MEMORY_SOURCE;
		fbdev->vb2->cfg = DMA_CFG_VAL;
		fbdev->vb2->x_count =
		    fbdev->modes[mode].xres + fbdev->modes[mode].boeft_blank;

		fbdev->vb2->x_modify = 0;
		fbdev->vb2->y_count = fbdev->modes[mode].vb2_lines;
		fbdev->vb2->y_modify = 0;

		/* Active Video Field 2 */

		fbdev->av2->start_addr =
		    (unsigned long)fbdev->fb_mem + fbdev->line_len;

		fbdev->av2->cfg = DMA_CFG_VAL;

		fbdev->av2->x_count =
		    fbdev->modes[mode].xres + fbdev->modes[mode].boeft_blank;

		fbdev->av2->x_modify = (fbdev->modes[mode].bpp / 8);
		fbdev->av2->y_count = fbdev->modes[mode].a_lines;

		fbdev->av2->y_modify =
		    (fbdev->modes[mode].xres - fbdev->modes[mode].boeft_blank +
		     1) * (fbdev->modes[mode].bpp / 8);

		return 1;
	}

error:
	l1_data_A_sram_free(fbdev->vb1);
	l1_data_A_sram_free(fbdev->av1);
	l1_data_A_sram_free(fbdev->vb2);
	l1_data_A_sram_free(fbdev->av2);

	return 0;
}

static int bfin_fb_mmap(struct fb_info *info, struct vm_area_struct *vma)
{
	/* we really dont need any map ... not sure how the smem_start will
	 * end up in the kernel
	 */

	struct adv7393fb_device *fbdev = to_adv7393fb_device(info);

	vma->vm_start = (int)fbdev->fb_mem;

	/*   VM_MAYSHARE limits for mprotect(), and must be set on nommu.
	 *   Other flags can be set, and are documented in
	 *   include/linux/mm.h
	 */

	vma->vm_flags |= VM_MAYSHARE;

	return 0;

}

static int bfin_config_dma(struct adv7393fb_device *fbdev)
{
	assert(fbdev->fb_mem);

	set_dma_x_count(CH_PPI, fbdev->descriptor_list_head->x_count);
	set_dma_x_modify(CH_PPI, fbdev->descriptor_list_head->x_modify);
	set_dma_y_count(CH_PPI, fbdev->descriptor_list_head->y_count);
	set_dma_y_modify(CH_PPI, fbdev->descriptor_list_head->y_modify);
	set_dma_start_addr(CH_PPI, fbdev->descriptor_list_head->start_addr);
	set_dma_next_desc_addr(CH_PPI,
			       fbdev->descriptor_list_head->next_desc_addr);
	set_dma_config(CH_PPI, fbdev->descriptor_list_head->cfg);

	return 1;
}

static void bfin_disable_dma(void)
{
	bfin_write_DMA0_CONFIG(bfin_read_DMA0_CONFIG() & ~DMAEN);
}

static void bfin_config_ppi(struct adv7393fb_device *fbdev)
{
#if defined(CONFIG_BF537) || defined(CONFIG_BF536) || defined(CONFIG_BF534)
	bfin_write_PORTG_FER(0xFFFF);	/* PPI[15:0]    */
	bfin_write_PORTF_FER(bfin_read_PORTF_FER() | 0x8300);	/* PF.15 PPI_CLK FS1 FS2 */
	bfin_write_PORT_MUX(bfin_read_PORT_MUX() & ~0x0E00);
#endif

	bfin_write_PPI_CONTROL(0x381E);
	bfin_write_PPI_FRAME(fbdev->modes[mode].tot_lines);
	bfin_write_PPI_COUNT(fbdev->modes[mode].xres +
			     fbdev->modes[mode].boeft_blank - 1);
	bfin_write_PPI_DELAY(fbdev->modes[mode].aoeft_blank - 1);
}

static void bfin_enable_ppi(void)
{
	bfin_write_PPI_CONTROL(bfin_read_PPI_CONTROL() | PORT_EN);
}

static void bfin_disable_ppi(void)
{
	bfin_write_PPI_CONTROL(bfin_read_PPI_CONTROL() & ~PORT_EN);
}

static inline int adv7393_write(struct i2c_client *client, u8 reg, u8 value)
{
   if (client) {
       return i2c_smbus_write_byte_data(client, reg, value);
    } else {
      printk(KERN_ERR "adv7393_read failed - check I2C Support\n");
      return(-1);
    }

}

static inline int adv7393_read(struct i2c_client *client, u8 reg)
{

   if (client) {
	return i2c_smbus_read_byte_data(client, reg);
    } else {
      printk(KERN_ERR "adv7393_read failed - check I2C Support\n");
      return(-1);
    }
}

static int
adv7393_write_block(struct i2c_client *client,
		    const u8 * data, unsigned int len)
{
	int ret = -1;
	u8 reg;

	while (len >= 2) {
		reg = *data++;
		if ((ret = adv7393_write(client, reg, *data++)) < 0)
			break;
		len -= 2;
	}
	return ret;
}

/*
 * Generic i2c probe * concerning the addresses: i2c wants 7 bit (without the r/w bit), so '>>1'
 */
static u16 normal_i2c[] = { I2C_ADV7393 >> 1, (I2C_ADV7393 >> 1) + 1,
	I2C_CLIENT_END
};

static u16 probe[2] = { I2C_CLIENT_END, I2C_CLIENT_END };
static u16 ignore[2] = { I2C_CLIENT_END, I2C_CLIENT_END };

static struct i2c_client_address_data addr_data = {
	.normal_i2c = normal_i2c,
	.probe = probe,
	.ignore = ignore,
};

static struct i2c_driver i2c_driver_adv7393;

static int
adv7393_detect_client(struct i2c_adapter *adapter, int address, int kind)
{
	int i;
	struct i2c_client *client;
	char *dname;

	printk(KERN_INFO
	       "adv7393.c: detecting adv7393 client on address 0x%x\n",
	       address << 1);

	/* Check if the adapter supports the needed features */
	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE_DATA))
		return 0;

	client = kzalloc(sizeof(struct i2c_client), GFP_KERNEL);
	if (client == 0)
		return -ENOMEM;

	client->addr = address;
	client->adapter = adapter;
	client->driver = &i2c_driver_adv7393;
	if ((client->addr == I2C_ADV7393 >> 1) ||
	    (client->addr == (I2C_ADV7393 >> 1) + 1)) {
		dname = adv7393_name;
	} else {
		/* We should never get here!!! */
		kfree(client);
		return 0;
	}
	strlcpy(I2C_NAME(client), dname, sizeof(I2C_NAME(client)));

	i = i2c_attach_client(client);
	if (i) {
		kfree(client);
		return i;
	}

	drv->i2c_adv7393_client = client;

	if (adv7393_write_block
	    (drv->i2c_adv7393_client, drv->modes[mode].adv7393_i2c_initd,
	     drv->modes[mode].adv7393_i2c_initd_len) < 0) {
		printk(KERN_ERR "%s_attach: init error\n",
		       I2C_NAME(drv->i2c_adv7393_client));
	}

	return 0;
}

static int adv7393_attach_adapter(struct i2c_adapter *adapter)
{
	printk(KERN_INFO
	       "adv7393.c: starting probe for adapter %s(0x%x)\n",
	       I2C_NAME(adapter), adapter->id);
	return i2c_probe(adapter, &addr_data, &adv7393_detect_client);
}

static int adv7393_detach_client(struct i2c_client *client)
{

	int err;

	err = i2c_detach_client(client);
	if (err) {
		return err;
	}

	kfree(client);

	return 0;
}

/* ----------------------------------------------------------------------- */

static struct i2c_driver i2c_driver_adv7393 = {
	.driver = {
		   .name = "adv7393",	/* name */
		   },

	.id = I2C_DRIVERID_ADV7170,

	.attach_adapter = adv7393_attach_adapter,
	.detach_client = adv7393_detach_client,
};

static int adv7393_mode(u16 mode)
{
	switch (mode) {
	case POWER_ON:
		adv7393_write(drv->i2c_adv7393_client, 0x00, 0x1E);	/* ADV7393 Sleep mode OFF */
		break;
	case POWER_DOWN:
		adv7393_write(drv->i2c_adv7393_client, 0x00, 0x1F);	/* ADV7393 Sleep mode ON */
		break;
	case BLANK_OFF:
		adv7393_write(drv->i2c_adv7393_client, 0x82, 0xCB);	/*Pixel Data Valid */
		break;
	case BLANK_ON:
		adv7393_write(drv->i2c_adv7393_client, 0x82, 0x8B);	/*Pixel Data Invalid */
		break;
	default:
		return -EINVAL;
		break;
	}
	return 0;
}

static irqreturn_t ppi_irq_error(int irq, void *dev_id, struct pt_regs *regs)
{

	struct adv7393fb_device *fbdev = (struct adv7393fb_device *)dev_id;

	u16 status = bfin_read_PPI_STATUS();

	pr_debug("%s: PPI Status = 0x%X \n", __FUNCTION__, status);

	if (status) {
		bfin_disable_dma();	/* TODO: Check Sequence */
		bfin_disable_ppi();
		bfin_clear_PPI_STATUS();
		bfin_config_dma(fbdev);
		bfin_enable_ppi();
	}

	return IRQ_HANDLED;

}

static int proc_output(char *buf)
{
	char *p;

	p = buf;
	p += sprintf(p,
		     "Usage:\necho 0x[REG][Value] > adv7393\nexample: echo 0x1234 >\
		 adv7393\nwrites 0x34 into Register 0x12\n");

	return p - buf;
}

static int
adv7393_read_proc(char *page, char **start, off_t off,
		  int count, int *eof, void *data)
{
	int len;

	len = proc_output(page);
	if (len <= off + count)
		*eof = 1;
	*start = page + off;
	len -= off;
	if (len > count)
		len = count;
	if (len < 0)
		len = 0;
	return len;

}

static int
adv7393_write_proc(struct file *file, const char __user * buffer,
		   unsigned long count, void *data)
{
	char line[8];
	unsigned int val;

	copy_from_user(line, buffer, count);
	val = simple_strtoul(line, NULL, 0);
	adv7393_write(drv->i2c_adv7393_client, val >> 8, val & 0xff);

	return count;
}

int __init bfin_adv7393_fb_init(void)
{
	int ret = 0;
	struct proc_dir_entry *entry;
	int num_modes = ARRAY_SIZE(known_modes);

	struct adv7393fb_device *fbdev = NULL;

	if (mem > 2) {
		printk(KERN_ERR
		       "\n bfin_adv7393_fb: mem out of allowed range [1;2]\n");
		return -EINVAL;
	}

	if (mode > num_modes) {
		printk(KERN_ERR "Mode %d: not supported", mode);
		return -EFAULT;
	}

	if (!(fbdev = kzalloc(sizeof(struct adv7393fb_device), GFP_KERNEL))) {
		printk(KERN_ERR "fail to allocate device private record");
		return -ENOMEM;
	}

	drv = fbdev;

	fbdev->modes = known_modes;

	printk(KERN_NOTICE "\nbfin_adv7393_fb: initializing: %s \n",
	       fbdev->modes[mode].name);

	fbdev->fb_len =
	    mem * fbdev->modes[mode].xres * fbdev->modes[mode].xres *
	    (fbdev->modes[mode].bpp / 8);

	fbdev->line_len =
	    fbdev->modes[mode].xres * (fbdev->modes[mode].bpp / 8);

	fbdev->fb_mem =
	    dma_alloc_coherent(NULL, fbdev->fb_len, &fbdev->dma_handle,
			       GFP_KERNEL);

	if (NULL == fbdev->fb_mem) {
		printk(KERN_ERR
		       "FB: couldn't allocate dma buffer (%d bytes) \n",
		       (u32) fbdev->fb_len);
		ret = -ENOMEM;
		goto out_5;
	}

	memset(fbdev->fb_mem, 0, fbdev->fb_len);

	fbdev->info.screen_base = (void *)fbdev->fb_mem;
	bfin_adv7393_fb_fix.smem_start = (int)fbdev->fb_mem;

	bfin_adv7393_fb_fix.smem_len = fbdev->fb_len;
	bfin_adv7393_fb_fix.line_length = fbdev->line_len;

	if (mem > 1)
		bfin_adv7393_fb_fix.ypanstep = 1;

	bfin_adv7393_fb_defined.red.length = 5;
	bfin_adv7393_fb_defined.green.length = 6;
	bfin_adv7393_fb_defined.blue.length = 5;

	bfin_adv7393_fb_defined.xres = fbdev->modes[mode].xres;
	bfin_adv7393_fb_defined.yres = fbdev->modes[mode].yres;
	bfin_adv7393_fb_defined.xres_virtual = fbdev->modes[mode].xres;
	bfin_adv7393_fb_defined.yres_virtual = mem * fbdev->modes[mode].yres;
	bfin_adv7393_fb_defined.bits_per_pixel = fbdev->modes[mode].bpp;

	fbdev->info.fbops = &bfin_adv7393_fb_ops;
	fbdev->info.var = bfin_adv7393_fb_defined;
	fbdev->info.fix = bfin_adv7393_fb_fix;
	fbdev->info.par = &bfin_par;
	fbdev->info.flags = FBINFO_DEFAULT;

	if (request_dma(CH_PPI, "BF5xx_PPI_DMA") < 0) {
		printk(KERN_ERR
		       "\n bfin_adv7393_fb: unable to request PPI DMA\n");
		ret = -EFAULT;
		goto out_4;
	}

	if (request_irq(IRQ_PPI_ERROR, (void *)ppi_irq_error, SA_INTERRUPT,
			"PPI ERROR", fbdev) < 0) {
		printk(KERN_ERR
		       "\n bfin_adv7393_fb: unable to request PPI ERROR IRQ\n");
		ret = -EFAULT;
		goto out_3;
	}

	disable_irq(IRQ_PPI_ERROR);

	if (i2c_add_driver(&i2c_driver_adv7393)) {
		printk(KERN_ERR "I2C Driver Initialisation failed\n");
		ret = -EFAULT;
		goto out_2;
	}

	if (register_framebuffer(&fbdev->info) < 0) {
		printk(KERN_ERR
		       "bfin_adv7393_fb: unable to register framebuffer\n");
		ret = -EFAULT;
		goto out_1;
	}

	printk(KERN_INFO "fb%d: %s frame buffer device\n",
	       fbdev->info.node, fbdev->info.fix.id);
	printk(KERN_INFO "fb memory address : 0x%p\n", fbdev->fb_mem);

	if ((entry = create_proc_entry("driver/adv7393", 0, NULL)) == NULL) {
		printk(KERN_ERR
		       "bfin_adv7393_fb: unable to create /proc entry\n");
		ret = -EFAULT;
		goto out_0;
	}

	entry->read_proc = adv7393_read_proc;
	entry->write_proc = adv7393_write_proc;
	entry->data = NULL;

	return 0;

      out_0:
	unregister_framebuffer(&fbdev->info);
      out_1:
	i2c_del_driver(&i2c_driver_adv7393);
      out_2:
	free_irq(IRQ_PPI_ERROR, fbdev);
      out_3:
	free_dma(CH_PPI);
      out_4:
	dma_free_coherent(NULL, fbdev->fb_len, fbdev->fb_mem,
			  fbdev->dma_handle);
      out_5:
	kfree(fbdev);

	return ret;
}

static int bfin_adv7393_fb_open(struct fb_info *info, int user)
{
	struct adv7393fb_device *fbdev = to_adv7393fb_device(info);

	fbdev->info.screen_base = (void *)fbdev->fb_mem;
	bfin_adv7393_fb_fix.smem_start = (int)fbdev->fb_mem;
	if (!fbdev->info.screen_base) {
		printk(KERN_ERR "bfin_adv7393_fb: unable to map device\n");
		return -ENOMEM;
	}

	dma_desc_list(fbdev, BUILD);
	enable_irq(IRQ_PPI_ERROR);
	bfin_config_ppi(fbdev);
	bfin_config_dma(fbdev);
	bfin_enable_ppi();
	adv7393_mode(BLANK_OFF);

	return 0;
}

static int bfin_adv7393_fb_release(struct fb_info *info, int user)
{

	struct adv7393fb_device *fbdev = to_adv7393fb_device(info);

	adv7393_mode(BLANK_ON);
	disable_irq(IRQ_PPI_ERROR);
	bfin_disable_dma();
	bfin_disable_ppi();
	dma_desc_list(fbdev, DESTRUCT);

	return 0;
}

static int
bfin_adv7393_fb_check_var(struct fb_var_screeninfo *var, struct fb_info *info)
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

static int bfin_adv7393_fb_set_par(struct fb_info *info)
{
	printk(KERN_INFO "%s: called ... not implemented\n", __FUNCTION__);
	return -EINVAL;
}

static int
bfin_adv7393_fb_pan_display(struct fb_var_screeninfo *var, struct fb_info *info)
{
	int dy;
	u32 dmaaddr;
	struct adv7393fb_device *fbdev = to_adv7393fb_device(info);

	if (!var || !info)
		return -EINVAL;

	if (var->xoffset - info->var.xoffset) {
		/* No support for X panning for now! */
		return -EINVAL;
	}
	dy = var->yoffset - info->var.yoffset;

	if (dy) {
		pr_debug("%s: Panning screen of %d lines\n", __FUNCTION__, dy);

		dmaaddr = fbdev->av1->start_addr;
		dmaaddr += (info->fix.line_length * dy);
		/* TODO: Wait for current frame to finished */

		fbdev->av1->start_addr = (unsigned long)dmaaddr;
		fbdev->av2->start_addr = (unsigned long)dmaaddr + fbdev->line_len;
	}

	return 0;

}

/* 0 unblank, 1 blank, 2 no vsync, 3 no hsync, 4 off */
static int bfin_adv7393_fb_blank(int blank, struct fb_info *info)
{
	switch (blank) {

	case VESA_NO_BLANKING:
		/* Turn on panel */
		adv7393_mode(BLANK_OFF);
		break;

	case VESA_VSYNC_SUSPEND:
	case VESA_HSYNC_SUSPEND:
	case VESA_POWERDOWN:
		/* Turn off panel */
		adv7393_mode(BLANK_ON);
		break;

	default:
		return -EINVAL;
		break;
	}
	return 0;
}

static void
bfin_adv7393_fb_fillrect(struct fb_info *info, const struct fb_fillrect *rect)
{
	printk(KERN_INFO "%s: called ... not implemented\n", __FUNCTION__);
}

static void
bfin_adv7393_fb_imageblit(struct fb_info *info, const struct fb_image *image)
{
	printk(KERN_INFO "%s: called ... not implemented\n", __FUNCTION__);
}

static void __exit bfin_adv7393_fb_exit(void)
{
	adv7393_mode(POWER_DOWN);

	if (drv->fb_mem)
		dma_free_coherent(NULL, drv->fb_len, drv->fb_mem, drv->dma_handle);
	free_dma(CH_PPI);
	free_irq(IRQ_PPI_ERROR, drv);
	unregister_framebuffer(&drv->info);
	i2c_del_driver(&i2c_driver_adv7393);
	remove_proc_entry("driver/adv7393", NULL);
	kfree(drv);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michael Hennerich <hennerich@blackfin.uclinux.org>");
MODULE_DESCRIPTION("Frame buffer driver for ADV7393/2 Video Encoder");

module_param(mode, int, 0);
MODULE_PARM_DESC(mode,
	"Video Mode (0=NTSC,1=PAL,2=NTSC 640x480,3=PAL 640x480,4=NTSC YCbCr input,5=PAL YCbCr input)");

module_param(mem, int, 0);
MODULE_PARM_DESC(mem,
	"Size of frame buffer memory 1=Single 2=Double Size"
	"(allows y-panning / frame stacking)");

module_init(bfin_adv7393_fb_init);
module_exit(bfin_adv7393_fb_exit);
