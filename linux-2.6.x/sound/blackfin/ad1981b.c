/*
 * File:         ad1981b.c 
 * Description:  sound driver for ad1981 (ac97) on sport0/dma1 on bf53x
 * 
 * Rev:          $Id$
 * Created:      
 * Author:       Luuk van Dijk, Bas Vermeulen
 * mail:         blackfin@buyways.nl
 * 
 * Copyright (C) 2003 Luuk van Dijk & Bas Vermeulen, BuyWays B.V.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/sound.h>
#include <linux/soundcard.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <asm/ptrace.h>
#include <asm/signal.h>
#include <asm/irq.h>
#include <asm/uaccess.h>
#include <asm/blackfin.h>
#include "ac97_sport.h"
#include "bf53x_structs.h"

#undef AD1981B_TEST   	/* define this to put in loopback mode on detection */
#undef AD1981B_DEBUG	/* define this to enable debugging */
#if defined(AD1981B_DEBUG)
#undef AD1981B_DEBUG_NR_OF_INTS /* define this to show the interrupt load */
#undef AD1981B_DEBUG_DUMP_REGS	 /* define this to dump the registers */
#endif

#define BUFFER_SIZE	0x2000
#define FRAGMENT_SIZE	0x0800
/*
 * the physical device is now a static variable in ac97_sport.c
 */

#ifdef IRQ_SPORT0_RX
static void ad1981b_rx_handler(int irq, void *dev_id, struct pt_regs *regs)
{
	static unsigned long last_print = 0;
	static int rx_ints_per_jiffie = 0;
	
	if (ac97_sport_handle_rx() == 0)
		rx_ints_per_jiffie++;
#  ifdef AD1981B_DEBUG
	if (last_print == 0) last_print = jiffies;
	
	if ((jiffies - last_print) > (32 * HZ))
	{
#    ifdef AD1981B_DEBUG_DUMP_REGS
		printk(KERN_INFO "ad1981b: Register dump:\n");
		for (int i = 0; i < 128; i += 2)
		{
			__u16 regval;
			int dirty;
			dirty = ac97_sport_get_register(i, &regval);
			if (dirty == 0)
				printk(KERN_INFO "ad1981b: Register 0x%02x - "
					"0x%04x\n", i, regval);
		}
#    endif
#    ifdef AD1981B_DEBUG_NR_OF_INTS
		printk(KERN_INFO "ad1981b: %d rx interrupts per second\n",
				rx_ints_per_jiffie/32);
		rx_ints_per_jiffie = 0;
#    endif
		last_print = jiffies;
	}
#  endif
}
#endif

#ifdef IRQ_SPORT0_TX
static void ad1981b_tx_handler(int irq, void *dev_id, struct pt_regs *regs)
{
	static unsigned long last_print = 0;
	static int tx_ints_per_jiffie = 0;
	if (ac97_sport_handle_tx() == 0)
		tx_ints_per_jiffie++;
#  ifdef AD1981B_DEBUG
	if (last_print == 0) last_print = jiffies;
	
	if ((jiffies - last_print) > (32 * HZ))
	{
#    ifdef AD1981B_DEBUG_NR_OF_INTS
		printk(KERN_INFO "ad1981b: %d tx interrupts per second\n",
				tx_ints_per_jiffie/32);
		tx_ints_per_jiffie = 0;
#    endif
		last_print = jiffies;
	}
#  endif
}
#endif

#ifdef IRQ_SPORT0
static void ad1981b_handler(int irq, void *dev_id, struct pt_regs *regs)
{
	static unsigned long last_print = 0;
	static int ints_per_jiffie = 0;
	static int tx_ints_per_jiffie = 0;
	static int rx_ints_per_jiffie = 0;
	int i, dirty;
	__u16 regval;
	int irqstatus;
	
	irqstatus = ac97_sport_handle_irq();
#ifdef AD1981B_DEBUG	
	if (last_print == 0) last_print = jiffies;
	
	if ((jiffies - last_print) > (32*HZ))
	{
#ifdef AD1981B_DEBUG_DUMP_REGS
		printk(KERN_INFO "ad1981b: Register dump:\n");
		for (i = 0; i < 128; i += 2)
		{
			dirty = ac97_sport_get_register(i, &regval);
			if (dirty == 0)
				printk(KERN_INFO "ad1981b: Register 0x%02x - "
					"0x%04x\n", i, regval);
		}
#endif
#ifdef AD1981B_DEBUG_NR_OF_INTS
		printk(KERN_INFO "ad1981b: %d (%d rx/ %d tx) interrupts per second.\n",
			ints_per_jiffie/64, 
			rx_ints_per_jiffie/64, 
			tx_ints_per_jiffie/64);
#endif
		ints_per_jiffie = rx_ints_per_jiffie = tx_ints_per_jiffie = 0;
		last_print = jiffies;
	} else {
		ints_per_jiffie++;
		if (irqstatus & 0x01)
			rx_ints_per_jiffie++;
		if (irqstatus & 0x02)
			tx_ints_per_jiffie++;
	}
#endif	
}
#endif

/*
 * the kernel representation
 */

int dev_audio, dev_mixer;


/*
 * mixer methods
 */



static loff_t ad1981b_mixer_llseek(struct file *file, loff_t offset, int origin)
{
	return -ESPIPE;
}

static int ad1981b_mixer_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{

	int val;
  if (cmd == SOUND_MIXER_INFO) {
    return 0;
  }
  if (cmd == SOUND_OLD_MIXER_INFO) {
    return 0;
  }
  if (cmd == OSS_GETVERSION)
    return put_user(SOUND_VERSION, (int *)arg);
  
  if (_IOC_TYPE(cmd) != 'M' || _IOC_SIZE(cmd) != sizeof(int))
    return -EINVAL;

  if (_IOC_DIR(cmd) != (_IOC_WRITE|_IOC_READ))
    return -EINVAL;
  
  if (_IOC_DIR(cmd) == _IOC_READ) {

    unsigned int val=0;

    switch (_IOC_NR(cmd)) {
    case SOUND_MIXER_RECSRC:     /* give them the current record source */
    case SOUND_MIXER_DEVMASK:    /* give them the supported mixers */
    case SOUND_MIXER_RECMASK:    /* Arg contains a bit for each supported recording source */
    case SOUND_MIXER_STEREODEVS: /* Mixer channels supporting stereo */
    case SOUND_MIXER_CAPS:
    default: /* read a specific mixer */
    } // switch

    return put_user(val,(int *)arg);
    
  } else { // if _IOC_READ 

    if (get_user(val, (int *)arg))
      return -EFAULT;
    
    switch (_IOC_NR(cmd)) {
    case SOUND_MIXER_RECSRC: /* Arg contains a bit for each recording source */
    default:
    } // switch

  }

  return -EINVAL;

} // mixer_ioctl





static int ad1981b_mixer_open(struct inode *inode, struct file *file)
{

  return -ENODEV;
}



static int ad1981b_mixer_release(struct inode *inode, struct file *file)
{
	return 0;
}



static struct file_operations ad1981b_mixer_fops = {
	owner:		THIS_MODULE,
	llseek:		ad1981b_mixer_llseek,
	ioctl:		ad1981b_mixer_ioctl,
	open:		ad1981b_mixer_open,
	release:	ad1981b_mixer_release,
};



/*
 * dsp methods
 */





static loff_t ad1981b_llseek(struct file *file, loff_t offset, int origin)
{
	return -ESPIPE;
}

#ifndef NO_MM
#warning "please map buffer to kernel space in ad1981b_read!"
#endif

static ssize_t ad1981b_read(struct file *file, char *buffer, size_t count, loff_t *ppos){

  size_t  toread;
  ssize_t ret = 0;
  
  if (ppos != &file->f_pos)
    return -ESPIPE;
  
  count &= ~3;
  
  while (count > 0){
    
    toread = ac97_audio_read_min_bytes(); /* available */
    
    if (toread > count)
      toread = count;
    
    if (toread == 0){
      
      if (file->f_flags & O_NONBLOCK){
	ret = ret ? ret : -EAGAIN;
	goto rec_return_free;
      }
      
      if (!ac97_wait_for_audio_read_with_timeout(HZ)){
	printk(KERN_INFO "ad1981b: Timeout waiting to read audio\n");
      }
      
      if (signal_pending(current)){
	ret = ret ? ret : -ERESTARTSYS;
	goto rec_return_free;
      }
      
      continue;

    }
    
    toread = ac97_audio_read(buffer, toread);
    
    count  -= toread;
    buffer += toread;
    ret    += toread;
    
  }
  
 rec_return_free:
  return ret;

}


#ifndef NO_MM
#warning "please map buffer to kernel space in ad1981b_read!"
#endif


static ssize_t ad1981b_write(struct file *file, const char *buffer, size_t count, loff_t *ppos){

  ssize_t ret = 0;
  int towrite;
  
  if (ppos != &file->f_pos)
    return -ESPIPE;
  
  
  count &= ~3;
  
  while (count > 0){

    towrite = ac97_audio_write_max_bytes();
    
    if (towrite > count)
      towrite = count;
    
    if (towrite != count){

      if (file->f_flags & O_NONBLOCK){
	  ret = ret ? ret : -EAGAIN;
	  goto play_return_free;
      }
      
      if (!ac97_wait_for_audio_write_with_timeout(HZ)){
	printk(KERN_INFO "ad1981b: Timeout waiting to write audio.\n");
      }

      if (signal_pending(current)){

	ret = ret ? ret : -ERESTARTSYS;
	goto play_return_free;
      }
      continue;

    }

    towrite = ac97_audio_write(buffer, towrite);
    count  -= towrite;
    buffer += towrite;
    ret += towrite;

  }

 play_return_free:
  return ret;

}

static unsigned int ad1981b_poll(struct file *file, struct poll_table_struct *wait)
{
	unsigned int mask = 0;

	if (file->f_mode & FMODE_WRITE)
		poll_wait(file, ac97_get_write_waitqueue(), wait);
	if (file->f_mode & FMODE_READ)
		poll_wait(file, ac97_get_read_waitqueue(), wait);

	if (file->f_mode & FMODE_READ)
		if (ac97_audio_read_min_bytes() >= FRAGMENT_SIZE)
			mask |= POLLIN | POLLRDNORM;
	if (file->f_mode & FMODE_WRITE)
		if (ac97_audio_write_max_bytes() >= FRAGMENT_SIZE)
			mask |= POLLOUT | POLLWRNORM;

	return mask;
}

static int ad1981b_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
	audio_buf_info abinfo;
	int val;

  switch (cmd) {
  case OSS_GETVERSION:
	  return put_user(SOUND_VERSION, (int *)arg);
  case SNDCTL_DSP_SYNC:
	  if (file->f_mode & FMODE_WRITE)
		  
  case SNDCTL_DSP_SETDUPLEX:
	  return 0;
  case SNDCTL_DSP_GETCAPS:
	  return put_user(DSP_CAP_DUPLEX | DSP_CAP_REALTIME,
			  (int *)arg);
  case SNDCTL_DSP_RESET:
	  return 0;
  case SNDCTL_DSP_SPEED:      // needed: 48000
	  return 48000;
  case SNDCTL_DSP_STEREO:
	  return 0;
  case SNDCTL_DSP_CHANNELS:   // needed: 2 ONLY stereo!!
	  return put_user(2, (int *)arg);
  case SNDCTL_DSP_GETFMTS:    // needed: only AFMT_S16_LE
	  return put_user(AFMT_S16_LE, (int *)arg);
  case SNDCTL_DSP_SETFMT:     // needed: AFMT_S16_LE
	  return put_user(AFMT_S16_LE, (int *)arg);
  case SNDCTL_DSP_POST:
	  return 0;
  case SNDCTL_DSP_GETTRIGGER:
	  return 0;
  case SNDCTL_DSP_SETTRIGGER:
	  return 0;
  case SNDCTL_DSP_GETOSPACE:
	  if (!(file->f_mode & FMODE_WRITE))
		  return -EINVAL;
	  abinfo.fragsize = FRAGMENT_SIZE << 2;
	  abinfo.bytes = ac97_audio_write_max_bytes();
	  abinfo.fragstotal = BUFFER_SIZE / FRAGMENT_SIZE;
	  abinfo.fragments = abinfo.bytes / (FRAGMENT_SIZE << 2);
	  return copy_to_user((void *)arg, &abinfo, sizeof(abinfo)) ? 
		  -EFAULT : 0;
  case SNDCTL_DSP_GETISPACE:
	  if (!(file->f_mode & FMODE_READ))
		  return -EINVAL;
	  abinfo.fragsize = FRAGMENT_SIZE << 2;
	  abinfo.bytes = ac97_audio_read_min_bytes();
	  abinfo.fragstotal = BUFFER_SIZE / FRAGMENT_SIZE;
	  abinfo.fragments = abinfo.bytes / (FRAGMENT_SIZE << 2);
	  return copy_to_user((void *)arg, &abinfo, sizeof(abinfo)) ? 
		  -EFAULT : 0;
  case SNDCTL_DSP_NONBLOCK:
	  file->f_flags |= O_NONBLOCK;
	  return 0;
  case SNDCTL_DSP_GETODELAY:
  case SNDCTL_DSP_GETIPTR:
  case SNDCTL_DSP_GETOPTR:
	  return -EINVAL;
  case SNDCTL_DSP_GETBLKSIZE:
	  return put_user(FRAGMENT_SIZE << 2, (int *)arg);
  case SNDCTL_DSP_SETFRAGMENT:
	  if (get_user(val, (int *)arg))
		  return -EFAULT;
	  val = 1 << (val & 0xffff);
	  printk(KERN_INFO "ad1981b: Trying to set fragment size to %d\n", val);
	  if (val == FRAGMENT_SIZE << 2)
		  return 0;
	  else
		  return -EINVAL;
  case SNDCTL_DSP_SUBDIVIDE:
  case SOUND_PCM_READ_RATE:
	  return put_user(48000, (int *)arg);
  case SOUND_PCM_READ_CHANNELS:
	  return put_user(2, (int *)arg);
  case SOUND_PCM_READ_BITS:
	  return put_user(16, (int *)arg);
  case SOUND_PCM_WRITE_FILTER:
  case SNDCTL_DSP_SETSYNCRO:
  case SOUND_PCM_READ_FILTER:
    return -EINVAL;
  }

  return -EINVAL;

} // _ioctl




static int ad1981b_mmap(struct file *file, struct vm_area_struct *vma)
{
	return -EINVAL;
}


static int ad1981b_open(struct inode *inode, struct file *file)
{
	return 0;
}


static int ad1981b_release(struct inode *inode, struct file *file)
{
	ac97_sport_silence();
	return 0;
}

static struct file_operations ad1981b_audio_fops = {
	owner:		THIS_MODULE,
	llseek:		ad1981b_llseek,
	read:		ad1981b_read,
	write:		ad1981b_write,
	poll:		ad1981b_poll,
	ioctl:		ad1981b_ioctl,
	mmap:		ad1981b_mmap,
	open:		ad1981b_open,
	release:	ad1981b_release,
};


/*
 * module initialisation
 */



static int __init ad1981b_install(void)
{

	/* Install the audio device, register interrupts, etc */
	dev_audio = register_sound_dsp(&ad1981b_audio_fops, -1);
	dev_mixer = register_sound_mixer(&ad1981b_mixer_fops, -1);


	printk(KERN_INFO "Astent AD1981B driver loading...\n");
	ac97_sport_open(BUFFER_SIZE, FRAGMENT_SIZE);
#if defined(IRQ_SPORT0)
	if (request_irq(IRQ_SPORT0, &ad1981b_handler, SA_SHIRQ, "SPORT0 AC97 Codec", NULL))
	{
		printk(KERN_ERR "ad1981b: unable to allocate irq %d.\n",
				IRQ_SPORT0);
		unregister_sound_mixer(dev_mixer);
		unregister_sound_dsp(dev_audio);

		/* Unable to get irq. */
		ac97_sport_close();
		return -ENODEV;
	}
	printk(KERN_INFO "- Enabling IRQ %d\n", IRQ_SPORT0);
	enable_irq(IRQ_SPORT0);
#endif
#if defined(IRQ_SPORT0_RX)
	if (request_irq(IRQ_SPORT0_RX, &ad1981b_rx_handler, SA_SHIRQ, "SPORT0 RX", NULL))
	{
		printk(KERN_ERR "ad1981b: Unable to allocate irq %d.\n",
				IRQ_SPORT0_RX);
		unregister_sound_mixer(dev_mixer);
		unregister_sound_dsp(dev_audio);

		ac97_sport_close();
		return -ENODEV;
	}
	printk(KERN_INFO "- Enabling RX Interrupt (%d)\n", IRQ_SPORT0_RX);
	enable_irq(IRQ_SPORT0_RX);
#endif
#if defined(IRQ_SPORT0_TX)
	if (request_irq(IRQ_SPORT0_TX, &ad1981b_tx_handler, SA_SHIRQ, "SPORT0 TX", NULL))
	{
		printk(KERN_ERR "ad1981b: Unable to allocate irq %d.\n",
				IRQ_SPORT0_TX);
		unregister_sound_mixer(dev_mixer);
		unregister_sound_dsp(dev_audio);

		ac97_sport_close();
		return -ENODEV;
	}
	printk(KERN_INFO "- Enabling TX Interrupt (%d)\n", IRQ_SPORT0_TX);
	enable_irq(IRQ_SPORT0_TX);
#endif
#if defined(AC97_DEMO)
	printk(KERN_INFO "- Going into TalkThrough Mode\n");
	/*  set to talktrougth testing mode: rxbuf = txbuf, and init mixer */
	ac97_sport_set_talkthrough_mode();
#endif 
	printk(KERN_INFO "- Initializing\n");
	ac97_sport_start();

	printk(KERN_INFO "Astent AD1981B driver succesfully loaded.\n");

	return 0;
}

int __init init_ad1981b(void)
{
	/* Find the audio device */

	/* Install the found device */
	ad1981b_install();

	return 0;
}

module_init(init_ad1981b);
