/*
 * File:         bfdma.c
 * Based on:
 * Author:       Marc Hoffman
 *
 * Created:      11/15/2007
 * Description:  Blackfin 2D DMA engine low level driver interface code.
 *
 * Modified:
 *               Copyright 2004-2007 Analog Devices Inc.
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
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>

#include <linux/timer.h>
#include <asm/blackfin.h>
#include <asm-blackfin/gpio.h>
#include <asm/uaccess.h>
#include <asm/dma.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/proc_fs.h>

#define BFMDMA_DEV "bfmdma"
static int bfmdma_major=250; /* fixed MAJOR */

static struct proc_dir_entry *bfmdma_proc_entry;

typedef unsigned short uword;
typedef struct {
  uword sal;
  uword sah;
  uword cfg;
  uword xc;
  uword xm;
  uword yc;
  uword ym;
} dmadsc_t;

static struct file_operations bfmdma_fops = {
    NULL,
};                 /* nothing more, fill with NULLs */


static int bfmdma_open (struct inode * inode, struct file * filp)
{
    printk(KERN_INFO "driver: open: \n");
    return 0;
}

static int bfmdma_release (struct inode * inode, struct file * filp)
{
    printk(KERN_INFO "driver: release: \n");
    return 0;
}

static ssize_t bfmdma_read(struct file *filp, char *buf, size_t count, loff_t *f_pos)
{
    return 0;
}

static ssize_t bfmdma_write(struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
    return 0;
}

/* turn off the seek */
extern loff_t no_llseek(struct file *file, loff_t offset, int origin);

static int __init bfmdma_fs_init(void) {
    int ret;

    /* fill in the fops table */
    bfmdma_fops.owner   = THIS_MODULE;
    bfmdma_fops.open    = bfmdma_open;
    bfmdma_fops.release = bfmdma_release;
    bfmdma_fops.llseek  = no_llseek;
    /* register the driver, check for an error return */

    ret = register_chrdev(bfmdma_major, BFMDMA_DEV, &bfmdma_fops);
    if (ret < 0) {
        printk(KERN_INFO " bfmdma driver module error ret = %d\n", ret);
	return 1;
    }
    printk(KERN_INFO " bfmdma driver module set up OK\n");
    return 0;
}

static void bfmdma_pdesc (unsigned p)
{
  unsigned short *x = (unsigned short *)p;
  int i;
  int stop,end;
  unsigned long a;
  for (i=0;i<2;i++) {
    stop = (x[2]&0xff00) == 0;
    printk ("%p: ARY SAH/L: %04x%04x CFG: %04x X(%d,+%d) Y(%d,+%d)\n",
	    x, x[1],x[0],x[2],x[3],x[4],x[5],x[6]);
    a = (x[1]<<16)|x[0];
    printk ("        %04x%04x: %02x %02x %02x %02x\n", x[1],x[0],
	    *(unsigned char *)(a+0),
            *(unsigned char *)(a+1),
            *(unsigned char *)(a+2),
            *(unsigned char *)(a+3));
    x += 7;
    end = x[0] == 0xFFFF;
  }
}


static int
bfmdma_write_proc(struct file *file, const char __user * buffer,
		  unsigned long count, void *data)
{
  unsigned val;
  char line[128];
  unsigned int tmp;
  char *p = line;
  char *e;

  if (count > 127)
    return 0;

  copy_from_user(line, buffer, count);
  line[count]=0;
  e = &line[count];

  if (line[0]=='0')
    val = simple_strtoul (line, NULL, 0);
  else {
    while (p < e) {
      if (strnicmp ("chain", p, 5) == 0) {
	  p += 5;
	  p += sscanf (p, "=%i", &tmp);
	  bfmdma_pdesc (tmp);
      }
      p++; // consume delimiter space
    }
  }
  return count;
}

static int
bfmdma_read_proc (char *buffer, char **start, off_t offset, int cnt,
		 int *eof, void *data)
{
  char *head = buffer;
  unsigned short s0_irqstat = bfin_read16 (MDMA_S0_IRQ_STATUS);
  unsigned short d0_irqstat = bfin_read16 (MDMA_D0_IRQ_STATUS);
  unsigned short s1_irqstat = bfin_read16 (MDMA_S1_IRQ_STATUS);
  unsigned short d1_irqstat = bfin_read16 (MDMA_D1_IRQ_STATUS);
  if (offset == 0) {
    head+=sprintf (head, "MDMA Status\n");
    head+=sprintf (head, "S0:    (RUN:%d DFETCH:%d ERR:%d DONE:%d)\n",
		   (s0_irqstat>>3)&1, (s0_irqstat>>2)&1, (s0_irqstat>>1)&1, (s0_irqstat)&1);
    head+=sprintf (head,"(S0) CFG: %04x IRQ: %04x CUR: %08x NXT: %08x\n",
		   bfin_read16(MDMA_S0_CONFIG),
		   bfin_read16(MDMA_S0_IRQ_STATUS),
		   bfin_read32(MDMA_S0_CURR_DESC_PTR),
		   bfin_read32(MDMA_S0_NEXT_DESC_PTR));
    head+=sprintf (head, "SAH/L: %08x X(%d,+%d) Y(%d,+%d)  current %08x cx: %d cy: %d\n",
		   bfin_read32(MDMA_S0_START_ADDR),
		   bfin_read16(MDMA_S0_X_COUNT),
		   bfin_read16(MDMA_S0_X_MODIFY),
		   bfin_read16(MDMA_S0_Y_COUNT),
		   bfin_read16(MDMA_S0_Y_MODIFY),
		   bfin_read32(MDMA_S0_CURR_ADDR),
		   bfin_read16(MDMA_S0_CURR_X_COUNT),
		   bfin_read16(MDMA_S0_CURR_Y_COUNT));
    head+=sprintf (head, "\n");

    head+=sprintf (head, "D0:    (RUN:%d DFETCH:%d ERR:%d DONE:%d)\n",
		   (d0_irqstat>>3)&1, (d0_irqstat>>2)&1, (d0_irqstat>>1)&1, (d0_irqstat)&1);
    head+=sprintf (head,"(D0) CFG: %04x IRQ: %04x CUR: %08x NXT: %08x\n",
		   bfin_read16(MDMA_D0_CONFIG),
		   bfin_read16(MDMA_D0_IRQ_STATUS),
		   bfin_read32(MDMA_D0_CURR_DESC_PTR),
		   bfin_read32(MDMA_D0_NEXT_DESC_PTR));
    head+=sprintf (head, "SAH/L: %08x X(%d,+%d) Y(%d,+%d)  current %08x cx: %d cy: %d\n",
		   bfin_read32(MDMA_D0_START_ADDR),
		   bfin_read16(MDMA_D0_X_COUNT),
		   bfin_read16(MDMA_D0_X_MODIFY),
		   bfin_read16(MDMA_D0_Y_COUNT),
		   bfin_read16(MDMA_D0_Y_MODIFY),
		   bfin_read32(MDMA_D0_CURR_ADDR),
		   bfin_read16(MDMA_D0_CURR_X_COUNT),
		   bfin_read16(MDMA_D0_CURR_Y_COUNT));
    head+=sprintf (head, "\n");

    head+=sprintf (head, "S1:    (RUN:%d DFETCH:%d ERR:%d DONE:%d)\n",
		   (s1_irqstat>>3)&1, (s1_irqstat>>2)&1, (s1_irqstat>>1)&1, (s1_irqstat)&1);
    head+=sprintf (head,"(S1) CFG: %04x IRQ: %04x CUR: %08x NXT: %08x\n",
		   bfin_read16(MDMA_S1_CONFIG),
		   bfin_read16(MDMA_S1_IRQ_STATUS),
		   bfin_read32(MDMA_S1_CURR_DESC_PTR),
		   bfin_read32(MDMA_S1_NEXT_DESC_PTR));
    head+=sprintf (head, "SAH/L: %08x X(%d,+%d) Y(%d,+%d)  current %08x cx: %d cy: %d\n",
		   bfin_read32(MDMA_S1_START_ADDR),
		   bfin_read16(MDMA_S1_X_COUNT),
		   bfin_read16(MDMA_S1_X_MODIFY),
		   bfin_read16(MDMA_S1_Y_COUNT),
		   bfin_read16(MDMA_S1_Y_MODIFY),
		   bfin_read32(MDMA_S1_CURR_ADDR),
		   bfin_read16(MDMA_S1_CURR_X_COUNT),
		   bfin_read16(MDMA_S1_CURR_Y_COUNT));
    head+=sprintf (head, "\n");

    head+=sprintf (head, "D1:    (RUN:%d DFETCH:%d ERR:%d DONE:%d)\n",
		   (d1_irqstat>>3)&1, (d1_irqstat>>2)&1, (d1_irqstat>>1)&1, (d1_irqstat)&1);
    head+=sprintf (head,"(D1) CFG: %04x IRQ: %04x CUR: %08x NXT: %08x\n",
		   bfin_read16(MDMA_D1_CONFIG),
		   bfin_read16(MDMA_D1_IRQ_STATUS),
		   bfin_read32(MDMA_D1_CURR_DESC_PTR),
		   bfin_read32(MDMA_D1_NEXT_DESC_PTR));

    head+=sprintf (head, "SAH/L: %08x X(%d,+%d) Y(%d,+%d)  current %08x cx: %d cy: %d\n",
		   bfin_read32(MDMA_D1_START_ADDR),
		   bfin_read16(MDMA_D1_X_COUNT),
		   bfin_read16(MDMA_D1_X_MODIFY),
		   bfin_read16(MDMA_D1_Y_COUNT),
		   bfin_read16(MDMA_D1_Y_MODIFY),
		   bfin_read32(MDMA_D1_CURR_ADDR),
		   bfin_read16(MDMA_D1_CURR_X_COUNT),
		   bfin_read16(MDMA_D1_CURR_Y_COUNT));
  }

  return head-buffer;
}

static int __init bfmdma_proc_init (void)
{
  bfmdma_proc_entry = create_proc_entry ("bfmdma",
					 S_IFREG|S_IRWXU|  S_IRWXG|S_IRWXO,
					 &proc_root);
  if(bfmdma_proc_entry) {
    bfmdma_proc_entry->read_proc  = bfmdma_read_proc;
    bfmdma_proc_entry->write_proc = bfmdma_write_proc;
    bfmdma_proc_entry->data       = NULL;
  }
  return 0;
}

static int __exit bfmdma_proc_exit(void)
{
  remove_proc_entry("bfmdma", &proc_root);
  return 0;
}


#define _XX(y) #y
#define XSTR(x) _XX(x)
#define hi(x) XSTR((x>>16)&0xffff)
#define lo(x) XSTR((x&0xffff))

void ex_dmach1 (void);

static int bfdma_opened;
static DEFINE_SPINLOCK(dma_lock);

static int __init bfmdmamod_init(void)
{
    int rval;
    u32 flags;

    spin_lock_irqsave(&dma_lock, flags);
    if (bfdma_opened) {
        spin_unlock_irqrestore(&dma_lock, flags);
        return -EMFILE;
    }

    if (request_dma(CH_MEM_STREAM1_SRC, "MEMDMA SRC") < 0) {
        panic("Unable to attach BlackFin MEMDMA DMA channel\n");
        bfdma_opened = 0;
        spin_unlock_irqrestore(&dma_lock, flags);
        return -EFAULT;
    }

    if (request_dma(CH_MEM_STREAM1_DEST, "MEMDMA DEST") < 0) {
        panic("Unable to attach BlackFin FBDMA DMA channel\n");
        bfdma_opened = 0;
        free_dma(CH_MEM_STREAM1_SRC);
        spin_unlock_irqrestore(&dma_lock, flags);
        return -EFAULT;
    }

    bfmdma_proc_init ();
    bfmdma_fs_init ();
    rval = bfin_request_exception (0xd, ex_dmach1);
    printk ("bfin_request_exception (13, ex_dmach1) = %d\n", rval);
    printk(KERN_INFO "bfmdma module init ex_dmach1: 0x%08x\n", ex_dmach1);

    bfdma_opened ++;
    spin_unlock_irqrestore(&dma_lock, flags);
    return 0;
}

static void __exit bfmdmamod_exit(void) 
{
    int ret,rval;

    free_dma(CH_MEM_STREAM1_SRC);
    free_dma(CH_MEM_STREAM1_DEST);

    bfdma_opened=0;

    bfmdma_proc_exit ();
    ret = unregister_chrdev(bfmdma_major, BFMDMA_DEV);
    rval = bfin_free_exception (0xd, ex_dmach1);
    printk ("bfin_free_exception (13, ex_dmach1) = %d\n", rval);

    printk(KERN_INFO "bfmdma module exit %d\n",ret);
}

module_init(bfmdmamod_init);
module_exit(bfmdmamod_exit);

MODULE_LICENSE("GPL");
