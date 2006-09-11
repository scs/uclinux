/*
 * Dummy Zaptel Driver for Zapata Telephony interface
 *
 * Required: usb-uhci module and kernel > 2.4.4 OR kernel > 2.6.0
 *
 * Written by Robert Pleh <robert.pleh@hermes.si>
 * 2.6 version by Tony Hoyle
 * Unified by Mark Spencer <markster@digium.com>
 *
 * Copyright (C) 2002, Hermes Softlab
 * Copyright (C) 2004, Digium, Inc.
 *
 * All rights reserved.
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#include <linux/version.h>

#ifndef VERSION_CODE
#  define VERSION_CODE(vers,rel,seq) ( ((vers)<<16) | ((rel)<<8) | (seq) )
#endif


#if LINUX_VERSION_CODE < VERSION_CODE(2,4,5)
#  error "This kernel is too old: not supported by this file"
#endif

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#ifdef STANDALONE_ZAPATA
#include "zaptel.h"
#else
#include <linux/zaptel.h>
#endif
#ifndef LINUX26
#include <linux/usb.h>
#include <linux/pci.h>
#include <asm/io.h>
#endif
#ifdef LINUX26
#include <linux/moduleparam.h>
#endif
#include "ztdummy.h"


#ifndef LINUX_VERSION_CODE
#  include <linux/version.h>
#endif

#ifndef VERSION_CODE
#  define VERSION_CODE(vers,rel,seq) ( ((vers)<<16) | ((rel)<<8) | (seq) )
#endif


#if LINUX_VERSION_CODE < VERSION_CODE(2,4,5)
#  error "This kernel is too old: not supported by this file"
#endif

static struct ztdummy *ztd;

static int debug = 0;

#ifdef LINUX26
/* New 2.6 kernel timer stuff */
static struct timer_list timer;
#else
#if LINUX_VERSION_CODE < VERSION_CODE(2,4,5)
#  error "This kernel is too old: not supported by this file"
#endif
/* Old UCHI stuff */
static    uhci_desc_t  *td;
static    uhci_t *s;
static int check_int = 0;
static int monitor = 0;

/* exported kernel symbols */
extern int insert_td (uhci_t *s, uhci_desc_t *qh, uhci_desc_t* new, int flags);
extern int alloc_td (uhci_t *s, uhci_desc_t ** new, int flags);
extern  int insert_td_horizontal (uhci_t *s, uhci_desc_t *td, uhci_desc_t* new);
extern int unlink_td (uhci_t *s, uhci_desc_t *element, int phys_unlink);
extern void fill_td (uhci_desc_t *td, int status, int info, __u32 buffer);
extern void uhci_interrupt (int irq, void *__uhci, struct pt_regs *regs);
extern int delete_desc (uhci_t *s, uhci_desc_t *element);
extern uhci_t **uhci_devices;

#endif


#ifdef LINUX26
static void ztdummy_timer(unsigned long param)
{
    zt_receive(&ztd->span);
    zt_transmit(&ztd->span);
    timer.expires = jiffies + 1;
    add_timer(&timer);
}
#else
static void ztdummy_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    unsigned short status;
    unsigned int io_addr = s->io_addr;

    status = inw (io_addr + USBSTS);
    if (status != 0)  {	/* interrupt from our USB port */
        zt_receive(&ztd->span);
        zt_transmit(&ztd->span);
        if (monitor && (check_int==0)) {      /* for testing if interrupt gets triggered*/
            check_int = 1;
            printk("ztdummy: interrupt triggered \n");     
        }   
     }
	return;
}
#endif

static int ztdummy_initialize(struct ztdummy *ztd)
{
	/* Zapata stuff */
	sprintf(ztd->span.name, "ZTDUMMY/1");
	sprintf(ztd->span.desc, "%s %d", ztd->span.name, 1);
	sprintf(ztd->chan.name, "ZTDUMMY/%d/%d", 1, 0);
	ztd->chan.chanpos = 1;
	ztd->span.chans = &ztd->chan;
	ztd->span.channels = 0;		/* no channels on our span */
	ztd->span.deflaw = ZT_LAW_MULAW;
	init_waitqueue_head(&ztd->span.maintq);
	ztd->span.pvt = ztd;
	ztd->chan.pvt = ztd;
	if (zt_register(&ztd->span, 0)) {
		return -1;
	}
	return 0;
}

int init_module(void)
{
#ifndef LINUX26
    int irq;
    spinlock_t mylock = SPIN_LOCK_UNLOCKED;
	
    if (uhci_devices==NULL){
        printk ("ztdummy: Uhci_devices pointer error.\n");
	    return -ENODEV;
    }
    s=*uhci_devices;     /* uhci device */
    if (s==NULL){
        printk ("ztdummy: No uhci_device found.\n");
	    return -ENODEV;
    }
#endif

    ztd = kmalloc(sizeof(struct ztdummy), GFP_KERNEL);
    if (ztd == NULL) {
	    printk("ztdummy: Unable to allocate memory\n");
	    return -ENOMEM;
    }

    memset(ztd, 0x0, sizeof(struct ztdummy));

    if (ztdummy_initialize(ztd)) {
	printk("ztdummy: Unable to intialize zaptel driver\n");
	kfree(ztd);
	return -ENODEV;
    }

#ifdef LINUX26
    init_timer(&timer);
    timer.function = ztdummy_timer;
    timer.expires = jiffies + 1;
    add_timer(&timer);
#else
    irq=s->irq;
    spin_lock_irq(&mylock);
    free_irq(s->irq, s);	/* remove uhci_interrupt temporaly */
    if (request_irq (irq, ztdummy_interrupt, SA_SHIRQ, "ztdummy", ztd)) {
    	spin_unlock_irq(&mylock);
		err("Our request_irq %d failed!",irq);
		kfree(ztd);
		return -EIO;
    }		/* we add our handler first, to assure, that our handler gets called first */
    if (request_irq (irq, uhci_interrupt, SA_SHIRQ, s->uhci_pci->driver->name, s)) {
        spin_unlock_irq(&mylock);
		err("Original request_irq %d failed!",irq);
    }
    spin_unlock_irq(&mylock);
    /* add td to usb host controller interrupt queue */
    alloc_td(s, &td, 0);
    fill_td(td, TD_CTRL_IOC, 0, 0);
    insert_td_horizontal(s, s->int_chain[0], td);	/* use int_chain[0] to get 1ms interrupts */
#endif	

    if (debug)
        printk("ztdummy: init() finished\n");
    return 0;
}


void cleanup_module(void)
{
#ifdef LINUX26
    del_timer(&timer);
#else
    free_irq(s->irq, ztd);  /* disable interrupts */
#endif
    zt_unregister(&ztd->span);
    kfree(ztd);
#ifndef LINUX26
	unlink_td(s, td, 1);
	delete_desc(s, td);
#endif
    if (debug)
        printk("ztdummy: cleanup() finished\n");
}



#ifdef LINUX26
module_param(debug, int, 0600);
#else
MODULE_PARM(debug, "i");
#endif

#ifndef LINUX26
MODULE_PARM(monitor, "i");
#endif
MODULE_DESCRIPTION("Dummy Zaptel Driver");
MODULE_AUTHOR("Robert Pleh <robert.pleh@hermes.si>");
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif
