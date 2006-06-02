/************************************************************
*
* Copyright (C) 2006, Analog Devices. All Rights Reserved
*
* FILE linux/drivers/video/bfin_adv7393fb.c
* PROGRAMMER(S): Michael Hennerich (Analog Devices Inc.)
*
* $Id$
*
* DATE OF CREATION: May. 24th 2006
*
* SYNOPSIS:
*
* DESCRIPTION: Frame buffer driver for ADV7393/2 video encoder
*
* CAUTION:
**************************************************************
* MODIFICATION HISTORY:
* Based on vga16fb.cCopyright 1999 Ben Pfaff <pfaffben@debian.org>
* and Petr Vandrovec <VANDROVE@vc.cvut.cz>
* Copyright 2004 Ashutosh Kumar Singh (ashutosh.singh@rrap-software.com)
************************************************************
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
************************************************************/

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

#include "bfin_adv7393fb.h"

//#define FBCONDEBUG 
#undef FBCONDEBUG 

#ifdef FBCONDEBUG
#  define DPRINTK(fmt, args...) printk(KERN_INFO "%s: " fmt, __FUNCTION__ , ## args)
#else
#  define DPRINTK(fmt, args...)
#endif 

static int bfin_adv7393_fb_open (struct fb_info *info, int user);
static int bfin_adv7393_fb_release (struct fb_info *info, int user);
static int bfin_adv7393_fb_check_var (struct fb_var_screeninfo *var,
				      struct fb_info *info);
static int bfin_adv7393_fb_set_par (struct fb_info *info);
static int bfin_adv7393_fb_pan_display (struct fb_var_screeninfo *var,
					struct fb_info *info);
static void bfin_adv7393_fb_fillrect (struct fb_info *info,
				      const struct fb_fillrect *rect);
static void bfin_adv7393_fb_imageblit (struct fb_info *info,
				       const struct fb_image *image);
static int bfin_adv7393_fb_blank (int blank, struct fb_info *info);
static int bfin_fb_mmap (struct fb_info *info, struct vm_area_struct *vma);

static void bfin_config_ppi (void);
static int bfin_config_dma (void *fb_buffer);
static void bfin_disable_dma (void);
static void bfin_enable_ppi (void);
static void bfin_disable_ppi (void);


extern unsigned long l1_data_A_sram_alloc (unsigned long size);
extern int l1_data_A_sram_free (unsigned long addr);


struct _dmasglarge_t *descriptor_list_head;
static dma_addr_t dma_handle;
static u16 *rgb_buffer;		/* RGB Buffer */
int id1;


/*
 * I2C driver
 */
#include <linux/i2c.h>
#include <linux/i2c-dev.h>

#define I2C_NAME(x) (x)->name

#include <linux/video_encoder.h>
#include <linux/videodev.h>

static inline int adv7393_write (struct i2c_client *client, u8 reg, u8 value);
static inline int adv7393_read (struct i2c_client *client, u8 reg);
static int adv7393_write_block (struct i2c_client *client, const u8 * data,
				unsigned int len);
static int adv7393_command (struct i2c_client *client, unsigned int cmd,
			    void *arg);
static char adv7393_name[] = "adv7393";

static char *norms[] = { "PAL", "NTSC" };

//#define TR0MODE     0x00
//#define TR0RST      0x80

static const unsigned char init_NTSC_TESTPATTERN[] = {
  0x00, 0x1C,			/*Power up all DACs and PLL */
  0x01, 0x00,			/*SD-Only Mode */
  0x80, 0x10,			/*SSAF Luma Filter Enabled, NTSC Mode */
  0x82, 0xCB,			/*Step control on, pixel data valid, pedestal on, PrPb SSAF on, CVBS/YC output. */
  0x84, 0x40,			/*SD Color Bar Test Pattern Enabled, DAC 2 = Luma, DAC 3 = Chroma */
};

static const unsigned char init_NTSC[] = {

  0x00, 0x1C,			/*Power up all DACs and PLL */
  0x01, 0x00,			/*SD-Only Mode */
  0x80, 0x10,			/*SSAF Luma Filter Enabled, NTSC Mode */
  0x82, 0xCB,			/*Step control on, pixel data valid, pedestal on, PrPb SSAF on, CVBS/YC output. */
  0x87, 0x80,			/*SD Color Bar Test Pattern Enabled, DAC 2 = Luma, DAC 3 = Chroma */
  0x86, 0x82,
  0x8B, 0x11,
  0x88, 0x20,
  0x8A, 0x0d,
};

static const unsigned char init_PAL[] = {
  0x00, 0x1C,			/*Power up all DACs and PLL */
  0x8C, 0xCB,			/* PAL Subcarrier Frequency */
  0x8D, 0x8A,			/* PAL Subcarrier Frequency */
  0x8E, 0x09,			/* PAL Subcarrier Frequency */
  0x8F, 0x2A,			/* PAL Subcarrier Frequency */
  0x01, 0x00,			/*SD-Only Mode */
  0x80, 0x11,			/*SSAF Luma Filter Enabled, PAL Mode */
  0x82, 0xCB,			/*Step control on, pixel data valid, pedestal on, PrPb SSAF on, CVBS/YC output. */
  0x87, 0x80,			/*SD Color Bar Test Pattern Enabled, DAC 2 = Luma, DAC 3 = Chroma */
  0x86, 0x82,
  0x8B, 0x11,
  0x88, 0x20,
  0x8A, 0x0d,
};

/*
 * card parameters
 */

static struct fb_info bfin_adv7393_fb;

static struct bfin_adv7393_fb_par
{
  /* structure holding blackfin / adv7393 paramters when
     screen is blanked */
  struct
  {
    unsigned char Mode;		/* ntsc/pal/? */
  } vga_state;
  atomic_t ref_count;
} bfin_par;

/* --------------------------------------------------------------------- */

static struct fb_var_screeninfo bfin_adv7393_fb_defined = {
  .xres = RGB_WIDTH,
  .yres = RGB_HEIGHT,
  .xres_virtual = RGB_WIDTH,
  .yres_virtual = RGB_HEIGHT,
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
  .smem_len = RGB_PHYS_SIZE,
  .type = FB_TYPE_PACKED_PIXELS,
  .visual = FB_VISUAL_TRUECOLOR,
  .xpanstep = 0,
  .ypanstep = 0,
  .line_length = RGB_WIDTH * 2,
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

static int
dma_desc_list (u16 arg)
{
  struct _dmasglarge_t *vb1 = NULL, *av1 = NULL, *vb2 = NULL, *av2 = NULL;

  if (arg)			/* Build */
    {
      vb1 =
	(struct _dmasglarge_t *)
	l1_data_A_sram_alloc (sizeof (struct _dmasglarge_t));
      if (vb1 == NULL)
	goto error;
      else
	memset (vb1, 0, sizeof (struct _dmasglarge_t));

      av1 =
	(struct _dmasglarge_t *)
	l1_data_A_sram_alloc (sizeof (struct _dmasglarge_t));
      if (av1 == NULL)
	goto error;
      else
	memset (av1, 0, sizeof (struct _dmasglarge_t));

      vb2 =
	(struct _dmasglarge_t *)
	l1_data_A_sram_alloc (sizeof (struct _dmasglarge_t));
      if (vb2 == NULL)
	goto error;
      else
	memset (vb2, 0, sizeof (struct _dmasglarge_t));

      av2 =
	(struct _dmasglarge_t *)
	l1_data_A_sram_alloc (sizeof (struct _dmasglarge_t));
      if (av2 == NULL)
	goto error;
      else
	memset (av2, 0, sizeof (struct _dmasglarge_t));

      /* Build linked DMA descriptor list */


      vb1->next_desc_addr = (unsigned long) av1;
      av1->next_desc_addr = (unsigned long) vb2;
      vb2->next_desc_addr = (unsigned long) av2;
      av2->next_desc_addr = (unsigned long) vb1;

      /* Save list head */
      descriptor_list_head = av2;

      vb1->start_addr = VB_DUMMY_MEMORY_SOURCE;
      vb1->cfg = DMA_CFG_VAL;
      vb1->x_count = DMA_X_CNT;
      vb1->x_modify = 0;
      vb1->y_count = VB1_LINES;
      vb1->y_modify = 0;

      av1->start_addr = (unsigned long)rgb_buffer;
      av1->cfg = DMA_CFG_VAL;
      av1->x_count = DMA_X_CNT;
      av1->x_modify = sizeof(RGB565);
      av1->y_count = ACTIVE_LINES;
      av1->y_modify = DMA_Y_MODIFY + sizeof(RGB565);

      vb2->start_addr = VB_DUMMY_MEMORY_SOURCE;
      vb2->cfg = DMA_CFG_VAL;
      vb2->x_count = DMA_X_CNT;
      vb2->x_modify = 0;
      vb2->y_count = VB2_LINES;
      vb2->y_modify = 0;

      av2->start_addr = (unsigned long)rgb_buffer + (RGB_WIDTH * sizeof(RGB565));
      av2->cfg = DMA_CFG_VAL;
      av2->x_count = DMA_X_CNT;
      av2->x_modify = sizeof(RGB565);
      av2->y_count = ACTIVE_LINES;
      av2->y_modify = DMA_Y_MODIFY + sizeof(RGB565);

      return 1;

    }				/* Destruct */
error:
  l1_data_A_sram_free ((unsigned long) vb1);
  l1_data_A_sram_free ((unsigned long) av1);
  l1_data_A_sram_free ((unsigned long) vb2);
  l1_data_A_sram_free ((unsigned long) av2);

  return 0;

}

static int
bfin_fb_mmap (struct fb_info *info, struct vm_area_struct *vma)
{
  /* we really dont need any map ... not sure how the smem_start will
     end up in the kernel
   */
  vma->vm_start = (int) rgb_buffer;
  return (int) rgb_buffer;
}


static int
bfin_config_dma (void *rgb_buffer)
{
  assert (rgb_buffer);

  set_dma_x_count (CH_PPI, descriptor_list_head->x_count);
  set_dma_x_modify (CH_PPI, descriptor_list_head->x_modify);
  set_dma_y_count (CH_PPI, descriptor_list_head->y_count);
  set_dma_y_modify (CH_PPI, descriptor_list_head->y_modify);
  set_dma_start_addr (CH_PPI, descriptor_list_head->start_addr);
  set_dma_next_desc_addr (CH_PPI, descriptor_list_head->next_desc_addr);
  set_dma_config (CH_PPI, descriptor_list_head->cfg);

 return 1;
}

static void
bfin_disable_dma (void)
{
  *pDMA0_CONFIG &= ~DMAEN;
}


static void
bfin_config_ppi (void)
{
#ifdef CONFIG_BF537
  *pPORTG_FER = 0xFFFF;		/* PPI[15:0]    */
  *pPORTF_FER |= 0x8300;	/* PF.15 PPI_CLK FS1 FS2 */
  *pPORT_MUX &= ~0x0E00;
#endif

  *pPPI_CONTROL = 0x381E;
  *pPPI_FRAME = LINES_PER_FRAME;
  *pPPI_COUNT = DMA_X_CNT - 1;
  *pPPI_DELAY = PPI_DELAY_CNT - 1;
}

static void
bfin_enable_ppi (void)
{
  *pPPI_CONTROL |= PORT_EN;
}

static void
bfin_disable_ppi (void)
{
  *pPPI_CONTROL &= ~PORT_EN;
}

static inline int
adv7393_write (struct i2c_client *client, u8 reg, u8 value)
{
  struct adv7393 *encoder = i2c_get_clientdata (client);

  encoder->reg[reg] = value;
  return i2c_smbus_write_byte_data (client, reg, value);
}

static inline int
adv7393_read (struct i2c_client *client, u8 reg)
{
  return i2c_smbus_read_byte_data (client, reg);
}

static int
adv7393_write_block (struct i2c_client *client,
		     const u8 * data, unsigned int len)
{
  int ret = -1;
  u8 reg;

  while (len >= 2)
    {
      reg = *data++;
      if ((ret = adv7393_write (client, reg, *data++)) < 0)
	break;
      len -= 2;
    }
  return ret;
}

static int
adv7393_command (struct i2c_client *client, unsigned int cmd, void *arg)
{
  struct adv7393 *encoder = i2c_get_clientdata (client);

  switch (cmd)
    {

    case ENCODER_GET_CAPABILITIES:
      {
	struct video_encoder_capability *cap = arg;

	cap->flags = VIDEO_ENCODER_PAL | VIDEO_ENCODER_NTSC;
	cap->inputs = 2;
	cap->outputs = 1;
      }
      break;

    case ENCODER_SET_NORM:
      {
	int iarg = *(int *) arg;

	printk (KERN_DEBUG "%s_command: set norm %d",
		I2C_NAME (client), iarg);

	switch (iarg)
	  {

	  case VIDEO_MODE_NTSC:
	    adv7393_write_block (client, init_NTSC, sizeof (init_NTSC));
//	    if (encoder->input == 0)
//	      adv7393_write (client, 0x02, 0x0e);
//	    adv7393_write (client, 0x07, TR0MODE | TR0RST);
//	    adv7393_write (client, 0x07, TR0MODE);
	    break;
	  case VIDEO_MODE_PAL:
	    adv7393_write_block (client, init_PAL, sizeof (init_PAL));
//	    if (encoder->input == 0)
//	      adv7393_write (client, 0x02, 0x0e);
//	    adv7393_write (client, 0x07, TR0MODE | TR0RST);
//	    adv7393_write (client, 0x07, TR0MODE);
	    break;

	  default:
	    printk (KERN_ERR "%s: illegal norm: %d\n",
		    I2C_NAME (client), iarg);
	    return -EINVAL;

	  }
	printk (KERN_DEBUG "%s: switched to %s\n", I2C_NAME (client),
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
static unsigned short normal_i2c[] =
  { I2C_ADV7393 >> 1, (I2C_ADV7393 >> 1) + 1,
  I2C_CLIENT_END
};

static unsigned short probe[2] = { I2C_CLIENT_END, I2C_CLIENT_END };
static unsigned short ignore[2] = { I2C_CLIENT_END, I2C_CLIENT_END };

static struct i2c_client_address_data addr_data = {
  .normal_i2c = normal_i2c,
  .probe = probe,
  .ignore = ignore,
};

static struct i2c_driver i2c_driver_adv7393;

static int
adv7393_detect_client (struct i2c_adapter *adapter, int address, int kind)
{
  int i;
  struct i2c_client *client;
  struct adv7393 *encoder;
  char *dname;

  printk (KERN_INFO
	  "adv7393.c: detecting adv7393 client on address 0x%x\n",
	  address << 1);

  /* Check if the adapter supports the needed features */
  if (!i2c_check_functionality (adapter, I2C_FUNC_SMBUS_BYTE_DATA))
    return 0;

  client = kmalloc (sizeof (struct i2c_client), GFP_KERNEL);
  if (client == 0)
    return -ENOMEM;
  memset (client, 0, sizeof (struct i2c_client));
  client->addr = address;
  client->adapter = adapter;
  client->driver = &i2c_driver_adv7393;
  if ((client->addr == I2C_ADV7393 >> 1) ||
      (client->addr == (I2C_ADV7393 >> 1) + 1))
    {
      dname = adv7393_name;
    }
  else
    {
      /* We should never get here!!! */
      kfree (client);
      return 0;
    }
  strlcpy (I2C_NAME (client), dname, sizeof (I2C_NAME (client)));

  encoder = kmalloc (sizeof (struct adv7393), GFP_KERNEL);
  if (encoder == NULL)
    {
      kfree (client);
      return -ENOMEM;
    }
  memset (encoder, 0, sizeof (struct adv7393));
#ifdef CONFIG_NTSC
  encoder->norm = VIDEO_MODE_NTSC;
#else /* CONFIG_PAL */
  encoder->norm = VIDEO_MODE_PAL;
#endif
  encoder->input = 0;
  encoder->enable = 1;
  i2c_set_clientdata (client, encoder);

  i = i2c_attach_client (client);
  if (i)
    {
      kfree (client);
      kfree (encoder);
      return i;
    }
#ifdef CONFIG_NTSC
  i = adv7393_write_block (client, init_NTSC, sizeof (init_NTSC));
#else /* CONFIG_PAL */
  i = adv7393_write_block (client, init_PAL, sizeof (init_PAL));
#endif
//        if (i >= 0) {
//                i = adv7393_write(client, 0x07, TR0MODE | TR0RST);
//                i = adv7393_write(client, 0x07, TR0MODE);
//                i = adv7393_read(client, 0x12);
//                printk(KERN_INFO "%s_attach: rev. %d at 0x%02x\n",
//                        I2C_NAME(client), i & 1, client->addr << 1);
//
//        }
  if (i < 0)
    {
      printk (KERN_ERR "%s_attach: init error 0x%x\n", I2C_NAME (client), i);
    }
  return 0;
}

static int
adv7393_attach_adapter (struct i2c_adapter *adapter)
{
  printk (KERN_INFO
	  "adv7393.c: starting probe for adapter %s (0x%x)\n",
	  I2C_NAME (adapter), adapter->id);
  return i2c_probe (adapter, &addr_data, &adv7393_detect_client);
}

static int
adv7393_detach_client (struct i2c_client *client)
{
  struct adv7393 *encoder = i2c_get_clientdata (client);
  int err;

  err = i2c_detach_client (client);
  if (err)
    {
      return err;
    }
  kfree (encoder);
  kfree (client);

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
  .command = adv7393_command,
};

static irqreturn_t
ppi_irq_error (int irq, void *dev_id, struct pt_regs *regs)
{

//   printk(KERN_ERR "PPI Status = 0x%X \n", *pPPI_STATUS);

  if (*pPPI_STATUS)
    {

      bfin_disable_dma ();	/* TODO: Check Sequence */
      bfin_disable_ppi ();
      *pPPI_STATUS = 0xFFFF;
      bfin_config_dma (rgb_buffer);
      bfin_enable_ppi ();
    }

  return IRQ_HANDLED;

}

int __init
bfin_adv7393_fb_init (void)
{
  int ret = 0;

  printk (KERN_NOTICE "bfin_adv7393_fb: initializing:\n");

  rgb_buffer =
    dma_alloc_coherent (NULL, RGB_PHYS_SIZE, &dma_handle, GFP_KERNEL);

  if (NULL == rgb_buffer)
    {
      printk (KERN_ERR "FB: couldn't allocate dma buffer.\n");
      return -ENOMEM;
    }

  memset (rgb_buffer, 0, RGB_PHYS_SIZE);

  bfin_adv7393_fb.screen_base = (void *) rgb_buffer;
  bfin_adv7393_fb_fix.smem_start = (int) rgb_buffer;
  if (!bfin_adv7393_fb.screen_base)
    {
      printk (KERN_ERR "bfin_adv7393_fb: unable to map device\n");
      ret = -ENOMEM;
    }
  bfin_adv7393_fb_defined.red.length = 5;
  bfin_adv7393_fb_defined.green.length = 6;
  bfin_adv7393_fb_defined.blue.length = 5;

  bfin_adv7393_fb.fbops = &bfin_adv7393_fb_ops;
  bfin_adv7393_fb.var = bfin_adv7393_fb_defined;
  /* our physical memory is dynamically allocated */
  bfin_adv7393_fb_fix.smem_start = (int) rgb_buffer;
  bfin_adv7393_fb.fix = bfin_adv7393_fb_fix;
  bfin_adv7393_fb.par = &bfin_par;
  bfin_adv7393_fb.flags = FBINFO_DEFAULT;

  if (register_framebuffer (&bfin_adv7393_fb) < 0)
    {
      printk (KERN_ERR "bfin_adv7393_fb: unable to register framebuffer\n");
      ret = -EINVAL;
    }
  printk (KERN_INFO "fb%d: %s frame buffer device\n",
	  bfin_adv7393_fb.node, bfin_adv7393_fb.fix.id);
  printk (KERN_INFO "fb memory address : 0x%p\n", rgb_buffer);
  i2c_add_driver (&i2c_driver_adv7393);

  if (request_dma (CH_PPI, "BF5xx_PPI_DMA") < 0)
    {
      printk (KERN_ERR "bfin_adv7393_fb: unable to request PPI DMA\n");
      return -EFAULT;
    }

//  *pDMA_TCPER = 0x0050;

  request_irq (IRQ_PPI_ERROR, (void *) ppi_irq_error, SA_INTERRUPT,
	       "PPI ERROR", NULL);
  disable_irq (IRQ_PPI_ERROR);

  return ret;
}



static int
bfin_adv7393_fb_open (struct fb_info *info, int user)
{

  bfin_adv7393_fb.screen_base = (void *) rgb_buffer;
  bfin_adv7393_fb_fix.smem_start = (int) rgb_buffer;
  if (!bfin_adv7393_fb.screen_base)
    {
      printk (KERN_ERR "bfin_adv7393_fb: unable to map device\n");
      return -ENOMEM;
    }

  dma_desc_list (BUILD);
  enable_irq (IRQ_PPI_ERROR);
  bfin_config_ppi ();
  bfin_config_dma (rgb_buffer);
  bfin_enable_ppi ();
  return 0;
}

static int
bfin_adv7393_fb_release (struct fb_info *info, int user)
{

  disable_irq (IRQ_PPI_ERROR);
  bfin_disable_dma ();		/* TODO: Check Sequence */
  bfin_disable_ppi ();

  dma_desc_list (DESTRUCT);

  return 0;
}

static int
bfin_adv7393_fb_check_var (struct fb_var_screeninfo *var,
			   struct fb_info *info)
{

	if (var->bits_per_pixel != 16) {
		DPRINTK(KERN_INFO ": depth not supported: %u BPP\n", var->bits_per_pixel);
		return -EINVAL;
	}

    if (info->var.xres != var->xres || info->var.yres != var->yres ||
        info->var.xres_virtual != var->xres_virtual ||
        info->var.yres_virtual != var->yres_virtual) {
		DPRINTK(KERN_INFO ": Resolution not supported: X%u x Y%u \n",var->xres,var->yres );
		return -EINVAL;
	}

	/*
	 *  Memory limit
	 */

    if ((info->fix.line_length * var->yres_virtual) > info->fix.smem_len) {
		DPRINTK(KERN_INFO ": Memory Limit requested yres_virtual = %u\n", var->yres_virtual);
        return -ENOMEM; 
    }

  return 0;
}

static int
bfin_adv7393_fb_set_par (struct fb_info *info)
{
  printk (KERN_INFO "bfin_adv7393_fb_set_par called not implemented\n");
  return -EINVAL;
}


static int
bfin_adv7393_fb_pan_display (struct fb_var_screeninfo *var,
			     struct fb_info *info)
{
  printk (KERN_INFO "bfin_adv7393_fb_pan_display called ... not implemented\n");
  return -EINVAL;
}

/* 0 unblank, 1 blank, 2 no vsync, 3 no hsync, 4 off */
static int
bfin_adv7393_fb_blank (int blank, struct fb_info *info)
{
  printk (KERN_INFO "bfin_adv7393_fb_blank called ... not implemented\n");
  return -EINVAL;
}

static void
bfin_adv7393_fb_fillrect (struct fb_info *info,
			  const struct fb_fillrect *rect)
{
  printk (KERN_INFO "bfin_adv7393_fb_fillrect called ... not implemented\n");
}

static void
bfin_adv7393_fb_imageblit (struct fb_info *info, const struct fb_image *image)
{
  printk (KERN_INFO "bfin_adv7393_fb_imageblit called ... not implemented\n");
}

static void __exit
bfin_adv7393_fb_exit (void)
{

  if (rgb_buffer)
    dma_free_coherent (NULL, RGB_PHYS_SIZE, rgb_buffer, dma_handle);
  free_irq (IRQ_PPI_ERROR, NULL);
  free_dma (CH_PPI);

//  *pDMA_TCPER = 0x0000;

  unregister_framebuffer (&bfin_adv7393_fb);
  i2c_del_driver (&i2c_driver_adv7393);
}

MODULE_LICENSE ("GPL");
module_init (bfin_adv7393_fb_init);
module_exit (bfin_adv7393_fb_exit);
