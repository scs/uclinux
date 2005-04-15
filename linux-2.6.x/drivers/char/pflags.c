/*
 *
 *    File:         pflags.c
 *    Rev:          $Id$
 *    Created:      Tue Apr 20 10:53:12 CEST 2004
 *    Author:       Bas Vermeulen, Luuk van Dijk
 *    mail:         lvd@mndmttr.nl
 *    Description:  pfbits driver for bf53x
 *                  
 *   Copyright (C) 2004 Luuk van Dijk/BuyWays B.V.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 ****************************************************************************
 * MODIFICATION HISTORY:
 * Jan 10, 2005   pflags.c Changed Michael Hennerich
 **************************************************************************** 
 */
 
	/*
	STAMP Board Connections are made as follows:
	PF2 -> GUI_LED1
	PF3 -> GUI_LED2
	PF4 -> GUI_LED3
	GUI_BUT1 -> PF5
	GUI_BUT2 -> PF6
	LAN_IRQ -> PF7
	GUI_BUT3 -> PF8
	*/

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/major.h>
#include <linux/poll.h>
#include <asm/uaccess.h>
#include <asm/blackfin.h>
#include <asm/irq.h>
#include "pflags.h"

#undef	DEBUG
//#define DEBUG

#ifdef DEBUG
#define DPRINTK(x...)	printk(x)
#else
#define DPRINTK(x...)	do { } while (0)
#endif 



#define PFLAG_MAJOR 253 //experimental

/* 0 / 1 meaning 0=input, 1=output */
/*                111111           */
/*                5432109876543210 */
#define PINCONF 0b0000000000011100



static wait_queue_head_t pflags_in_waitq;
static short pflags_laststate    = 0;
static short pflags_statechanged = 0;


static int pflags_ioctl(struct inode *inode, struct file *filp, uint cmd, unsigned long arg);


/* return the minor number or -ENODEV */

static int check_minor(struct inode* inode){
  
  int minor = MINOR(inode->i_rdev);
  
  if (minor > 15)
    return -ENODEV;
  
  return minor;

}


static int pflags_open(struct inode *inode, struct file *filp){
  if( check_minor(inode) < 0 ) return -ENODEV;
  return 0;
}

static int pflags_release(struct inode *inode, struct file *filp){
  if( check_minor(inode) < 0 ) return -ENODEV;
  return 0;
}


 static ssize_t pflags_read(struct file *filp, char * buf, size_t size, loff_t *offp)
{
  int minor = check_minor( filp->f_dentry->d_inode);
  
//  printk("pfbits driver for bf53x minor = %d\n",minor);
  
  const char* bit;

  if( minor < 0 ) return -ENODEV;
  
  if( size < 2 ) return -EMSGSIZE;

  bit = (*pFIO_FLAG_D & (1 << minor)) ?  "1" : "0";
    printk("pfbits pFIO_FLAG_D = %x\n",*pFIO_FLAG_D);

  return ( copy_to_user(buf, bit , 2) ) ? -EFAULT : 2;
  
}

static ssize_t pflags_write(struct file *filp, const char *buf, size_t size, loff_t *offp)
{
  
  int minor = check_minor( filp->f_dentry->d_inode );

  volatile unsigned short* set_or_clear;
  
//  printk("pfbits driver for bf53x minor = %d\n",minor);
  
  if( minor < 0 ) return -ENODEV;
  
  if( size < 2 ) return -EMSGSIZE;
  
  if( !buf ) return -EFAULT;

  set_or_clear = (buf[0] == '0') ? ((volatile unsigned short *)FIO_FLAG_C) : ((volatile unsigned short *)FIO_FLAG_S);

  *set_or_clear = (1 << minor);
  
  return size;

}


//static unsigned int pflags_poll(struct file *filp, struct poll_table_struct *wait){
//
//  int minor = check_minor( filp->f_dentry->d_inode );
//
//  int changed=0;
//
//  unsigned int mask = 0;
//  
//  if( minor < 0 ) return -ENODEV;
//
//
//    *pFIO_MASKA_C |= (1 << minor);    
//    *pFIO_MASKA_S |= (1 << minor);
//    *pFIO_INEN    |= (1 << minor);   
//    
//    
// 
// 
//  if (filp->f_mode & FMODE_READ){
//
//    do {
//
//      /* attention! this wakes up when /any/ of the flags changes */
//      poll_wait(filp, &pflags_in_waitq, wait);
//      
//      changed = pflags_statechanged & (1<<minor);
//      
//    } while( !changed );
//    
//    mask |= POLLIN | POLLRDNORM;
//  
//  }
//
//  /* we can always write */
//  if (filp->f_mode & FMODE_WRITE) 
//    mask |= POLLOUT | POLLWRNORM;
//
//  return mask;
//}
//
//
//
//static void pflags_irq_handler( int irq, void *dev_id, struct pt_regs *regs ){
//  
//  short pflags_nextstate = *pFIO_FLAG_D;
//  
//  *pFIO_FLAG_C = 0x20; /* clear irq status on interrupt lines */
//  
//  pflags_statechanged   = pflags_laststate ^ pflags_nextstate;
//  pflags_laststate      = pflags_nextstate;
//  
//  wake_up( &pflags_in_waitq );
//   
//}



static struct file_operations pflags_fops = {
  read:	   pflags_read,
  write:   pflags_write,
  ioctl:   pflags_ioctl,
  open:	   pflags_open,
  release: pflags_release,
//  poll:    pflags_poll
};


static int __init pflags_init(void){
  
  register_chrdev(PFLAG_MAJOR, "pflag", &pflags_fops);
  
//  if( request_irq (IRQ_PROG_INTA, pflags_irq_handler, SA_INTERRUPT, "pflags", NULL) ){
//    printk (KERN_WARNING "pflags: IRQ %d is not free.\n", IRQ_PROG_INTA);
//    return -EIO;
//  }

  init_waitqueue_head(&pflags_in_waitq);
  
    pflags_laststate = *pFIO_FLAG_D;
    pflags_statechanged = 0xffff; 
  
  printk("pfx: pfbits driver for bf53x IRQ %d\n",IRQ_PROG_INTA);
  
//  enable_irq(IRQ_PROG_INTA);
  
  return 0;
  
}

__initcall(pflags_init);

/***********************************************************
*
* FUNCTION NAME :pflags_ioctl
*
* INPUTS/OUTPUTS:
* in_inode - Description of openned file.
* in_filp - Description of openned file.
* in_cmd - Command passed into ioctl system call.
* in/out_arg - It is parameters which is specified by last command
*
* RETURN:
* 0 OK
* -EINVAL
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: 
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: 
* 
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
static int pflags_ioctl(struct inode *inode, struct file *filp, uint cmd, unsigned long arg)
{

  int minor = check_minor( filp->f_dentry->d_inode );

 
  if( minor < 0 ) return -ENODEV;

//printk("pfbits driver for bf53x minor = %d\n",minor);

    switch (cmd) 
    {
        case SET_FIO_DIR:
        {
            DPRINTK("pflags_ioctl: SET_FIO_DIR \n");

            if(arg) // OUTPUT
            {
				*pFIO_DIR |= (1 << minor);
            }
            else  // INPUT
            {
				*pFIO_DIR &= ~(1 << minor);
            }
            break;
        }
        case SET_FIO_POLAR:
        {
            DPRINTK("pflags_ioctl: SET_FIO_POLAR \n",arg);

            if(arg) // ACTIVELOW_FALLINGEDGE
            {
				*pFIO_POLAR |= (1 << minor);
            }
            else  // ACTIVEHIGH_RISINGEDGE
            {
				*pFIO_POLAR &= ~(1 << minor);
            }
            break;
        }
        case SET_FIO_EDGE:
        {
            DPRINTK("pflags_ioctl: SET_FIO_EDGE \n");

            if(arg) // EDGE
            {
				*pFIO_EDGE |= (1 << minor);
            }
            else  // LEVEL
            {
				*pFIO_EDGE &= ~(1 << minor);
            }
            break;
        }
        case SET_FIO_BOTH:
        {
            DPRINTK("pflags_ioctl: SET_FIO_BOTH \n");

            if(arg) // BOTHEDGES
            {
				*pFIO_BOTH |= (1 << minor);
            }
            else  // SINGLEEDGE
            {
				*pFIO_BOTH &= ~(1 << minor);
            }
            break;
        }
        case SET_FIO_INEN:
        {
            DPRINTK("pflags_ioctl: SET_FIO_INEN \n");

            if(arg) // OUTPUT_ENABLE
            {
				*pFIO_INEN |= (1 << minor);
            }
            else  // INPUT_DISABLE
            {
				*pFIO_INEN &= ~(1 << minor);
            }
            break;
        }
       default:
            return -EINVAL;
    }
    return 0;
}




