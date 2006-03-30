/*
 * can_read - can4linux CAN driver module
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 2001 port GmbH Halle/Saale
 *------------------------------------------------------------------
 * $Header$
 *
 *--------------------------------------------------------------------------
 *
 *
 *
 *--------------------------------------------------------------------------
 */


/**
* \file defs.h
* \author Name, port GmbH
* $Revision$
* $Date$
*
* Module Description 
* see Doxygen Doc for all possibilites
*
*
*
*/


/* needed for 2.4 */
#ifndef NOMODULE
# define __NO_VERSION__
# ifndef MODULE
#  define MODULE
# endif
#endif

#ifdef __KERNEL__
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

#ifdef __KERNEL__
#include <linux/init.h>
#include <linux/module.h>


#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/tty.h>
#include <linux/errno.h>
#include <linux/major.h>

#include <linux/version.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,12)
# include <linux/slab.h>
#else
# include <linux/malloc.h>
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,1,0)
#include <linux/poll.h>
#endif

#include <asm/io.h>
#include <asm/segment.h>
#include <asm/system.h>
#include <asm/irq.h>
#include <asm/dma.h>

#include <linux/mm.h>
#include <linux/signal.h>
#include <linux/timer.h>

#ifdef CONFIG_DEVFS_FS /* only if enabled, to avoid errors in 2.0 */
#include <linux/devfs_fs_kernel.h>
#endif

#include <asm/uaccess.h>

#define __lddk_copy_from_user(a,b,c) copy_from_user(a,b,c)
#define __lddk_copy_to_user(a,b,c) copy_to_user(a,b,c)


#include <linux/ioport.h>

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0) 
# include <linux/interrupt.h> 

#else
 /* For 2.4.x compatibility, 2.4.x can use */
typedef void irqreturn_t;
#define IRQ_NONE
#define IRQ_HANDLED
#define IRQ_RETVAL(x)

/* not available in k2.4.x */
static inline unsigned iminor(struct inode *inode)
{
	return MINOR(inode->i_rdev);
}
#endif





#if CAN4LINUX_PCI
# define _BUS_TYPE "PCI-"
/* the only one supported: EMS CPC-PCI */
# define PCI_VENDOR_CAN_EMS	0x110a
# define PCI_DEVICE_CAN 	0x2104

/* and CANPCI manufactured by Contemporary Controls Inc. */
# define PCI_VENDOR_CAN_CC	0x1571
# define PCI_DEVICE_CC_MASK 	0xC001
# define PCI_DEVICE_CC_CANopen 	0xC001
# define PCI_DEVICE_CC_CANDnet 	0xC002

/* and PCICAN manufactured by Kvaser */
# define PCI_VENDOR_CAN_KVASER	0x10e8
# define PCI_DEVICE_CAN_KVASER	0x8406


#elif CAN4LINUX_PCCARD
# define _BUS_TYPE "PC-Card-"
#else
# define _BUS_TYPE "ISA-"
#endif

#if    defined(ATCANMINI_PELICAN) \
    || defined(CCPC104)		\
    || defined(CPC_PCI)		\
    || defined(CC_CANPCI)	\
    || defined(IXXAT_PCI03)	\
    || defined(PCM3680)		\
    || defined(CPC_CARD)	\
    || defined(KVASER_PCICAN)
/* ---------------------------------------------------------------------- */

# ifdef  CAN_PORT_IO
#  define __CAN_TYPE__ _BUS_TYPE "PeliCAN-port I/O "
# else
#  ifdef  CAN_INDEXED_PORT_IO
#   define __CAN_TYPE__ _BUS_TYPE "PeliCAN-indexed port I/O "
#  else
#  define __CAN_TYPE__ _BUS_TYPE "PeliCAN-memory mapped "
#  endif
# endif

#elif defined(MCF5282)
#   define __CAN_TYPE__ _BUS_TYPE "FlexCAN "
/* ---------------------------------------------------------------------- */
#elif defined(UNCTWINCAN)
#   define __CAN_TYPE__ _BUS_TYPE "TwinCAN "
/* ---------------------------------------------------------------------- */
#elif defined(AD_BLACKFIN)
#   define __CAN_TYPE__ _BUS_TYPE "BlackFin-CAN "
/* ---------------------------------------------------------------------- */
#else
/* ---------------------------------------------------------------------- */
#endif

/* Length of the "version" string entry in /proc/.../version */
#define PROC_VER_LENGTH 30
/* Length of the "Chipset" string entry in /proc/.../version */
#define PROC_CHIPSET_LENGTH 30

/* kernels higher 2.3.x have a new kernel interface.
*  Since can4linux V3.x only kernel interfaces 2.4 an higher are supported.
*  This simplfies alot of things
* ******************/
#define __LDDK_WRITE_TYPE	ssize_t
#define __LDDK_CLOSE_TYPE	int
#define __LDDK_READ_TYPE	ssize_t
#define __LDDK_OPEN_TYPE	int
#define __LDDK_IOCTL_TYPE	int
#define __LDDK_SELECT_TYPE	unsigned int
#define __LDDK_FASYNC_TYPE	int

#define __LDDK_SEEK_PARAM 	struct file *file, loff_t off, size_t count
#define __LDDK_READ_PARAM 	struct file *file, char *buffer, size_t count, \
					loff_t *loff
#define __LDDK_WRITE_PARAM 	struct file *file, const char *buffer, \
					size_t count, loff_t *loff
#define __LDDK_READDIR_PARAM 	struct file *file, void *dirent, filldir_t count
#define __LDDK_SELECT_PARAM 	struct file *file, \
					struct poll_table_struct *wait
#define __LDDK_IOCTL_PARAM 	struct inode *inode, struct file *file, \
					unsigned int cmd, unsigned long arg
#define __LDDK_MMAP_PARAM 	struct file *file, struct vm_area_struct * vma
#define __LDDK_OPEN_PARAM 	struct inode *inode, struct file *file 
#define __LDDK_FLUSH_PARAM	struct file *file 
#define __LDDK_CLOSE_PARAM 	struct inode *inode, struct file *file 
#define __LDDK_FSYNC_PARAM 	struct file *file, struct dentry *dentry, \
					int datasync
#define __LDDK_FASYNC_PARAM 	int fd, struct file *file, int count 
#define __LDDK_CCHECK_PARAM 	kdev_t dev
#define __LDDK_REVAL_PARAM 	kdev_t dev

#define __LDDK_MINOR MINOR(file->f_dentry->d_inode->i_rdev)
#define __LDDK_INO_MINOR MINOR(inode->i_rdev)


#ifndef SLOW_DOWN_IO
# define SLOW_DOWN_IO __SLOW_DOWN_IO
#endif





/************************************************************************/
#include "debug.h"
/************************************************************************/
#ifdef __KERNEL__

extern __LDDK_READ_TYPE   can_read   (__LDDK_READ_PARAM);
extern __LDDK_WRITE_TYPE can_write (__LDDK_WRITE_PARAM);
extern __LDDK_SELECT_TYPE can_select (__LDDK_SELECT_PARAM);
extern __LDDK_IOCTL_TYPE  can_ioctl  (__LDDK_IOCTL_PARAM);
extern __LDDK_OPEN_TYPE   can_open   (__LDDK_OPEN_PARAM);
extern __LDDK_CLOSE_TYPE can_close (__LDDK_CLOSE_PARAM);
extern __LDDK_FASYNC_TYPE can_fasync (__LDDK_FASYNC_PARAM);

#endif 


/*---------- Default Outc value for some known boards
 * this depends on the transceiver configuration
 * some embedded CAN controllers even don't have this configuration option
 * 
 * the AT-CAN-MINI board uses optocoupler configuration as denoted
 * in the Philips application notes, so the OUTC value is 0xfa
 *
 */

#if   defined(ATCANMINI_BASIC) || defined(ATCANMINI_PELICAN)
# define CAN_OUTC_VAL           0xfa
# define IO_MODEL		'p'
# define STD_MASK		0xFFFFFFFF 
# include "sja1000.h"

#elif defined(IME_SLIMLINE)
# define CAN_OUTC_VAL           0xda
# define IO_MODEL		'm'
# define STD_MASK		0xFFFFFFFF 
# include "sja1000.h"

#elif defined(CPC_PCI)
# define CAN_OUTC_VAL           0xda
# define IO_MODEL		'm'
# define STD_MASK		0xFFFFFFFF 
# include "sja1000.h"

#elif defined(KVASER_PCICAN)
# define CAN_OUTC_VAL           0xda
# define IO_MODEL		'p'
# define STD_MASK		0xFFFFFFFF 
# include "sja1000.h"

#elif defined(IXXAT_PCI03)
# define CAN_OUTC_VAL           0x5e
# define IO_MODEL		'm'
# define STD_MASK		0xFFFFFFFF 
# include "sja1000.h"

#elif defined(PCM3680)
# define CAN_OUTC_VAL           0x5e
# define IO_MODEL		'm'
# define STD_MASK		0xFFFFFFFF 
# include "sja1000.h"

#elif defined(CCPC104)
# define CAN_OUTC_VAL           0xfa
# define IO_MODEL		'm'
# define STD_MASK		0xFFFFFFFF 
# include "sja1000.h"

#elif defined(MCF5282)
# define CAN_OUTC_VAL           0x5e
# define IO_MODEL		'm'
# define STD_MASK		0
# include "mcf5282.h"

#elif defined(AD_BLACKFIN)
# define CAN_OUTC_VAL           0x00
# define IO_MODEL		'm'
# define STD_MASK		0
# include "bf537.h"

#else 
# define CAN_OUTC_VAL           0x00
# define IO_MODEL		'm'
# define STD_MASK		0xFFFFFFFF 
# include "sja1000.h"
/* #error no CAN_OUTC_VAL */
#endif

/************************************************************************/
#include "can4linux.h"
/************************************************************************/
 /* extern volatile int irq2minormap[]; */
 /* extern volatile int irq2pidmap[]; */
extern u32 Can_pitapci_control[];
extern struct	pci_dev *Can_pcidev[];

/* number of supported CAN channels */
#ifndef MAX_CHANNELS
# define MAX_CHANNELS 4
#endif

#define MAX_BUFSIZE 64
/* #define MAX_BUFSIZE 1000 */
/* #define MAX_BUFSIZE 4 */

/* highest supported interrupt number */
#define MAX_IRQNUMBER	25
/* max number of bytes used for the device name in the inode 'can%d' */
#define MAXDEVNAMELENGTH 10

#define BUF_EMPTY    0
#define BUF_OK       1
#define BUF_FULL     BUF_OK
#define BUF_OVERRUN  2
#define BUF_UNDERRUN 3


 typedef struct {
	int head;
        int tail;
        int status;
	int active;
	char free[MAX_BUFSIZE];
        canmsg_t data[MAX_BUFSIZE];
 } msg_fifo_t;



#ifdef CAN_USE_FILTER
 #define MAX_ID_LENGTH 11
 #define MAX_ID_NUMBER (1<<11)

 typedef struct {
	unsigned    use;
	unsigned    signo[3];
	struct {
		unsigned    enable    : 1;
		unsigned    timestamp : 1;
		unsigned    signal    : 2;
		canmsg_t    *rtr_response;
	} filter[MAX_ID_NUMBER];
 } msg_filter_t;



 extern msg_filter_t Rx_Filter[];
#endif

 extern msg_fifo_t Tx_Buf[];
 extern msg_fifo_t Rx_Buf[];
 extern canmsg_t last_Tx_object[];    /* used for selreception of messages */

/* extern int Can_RequestIrq(int minor, int irq, irq_handler_t handler); */
/* extern int Can_RequestIrq(int minor, int irq, irqservice_t handler); */
extern int Can_RequestIrq(int minor, int irq, 
	irqreturn_t (*handler)(int, void *, struct pt_regs *));


extern wait_queue_head_t CanWait[];
extern wait_queue_head_t CanOutWait[];

extern unsigned char *can_base[];
extern unsigned int   can_range[];
#endif		/*  __KERNEL__ */

extern int IRQ_requested[];
extern int Can_minors[];			/* used as IRQ dev_id */
extern int selfreception[];			/* flag  1 = On */
extern int timestamp[];				/* flag  1 = On */
extern int wakeup[];				/* flag  1 = On */


/************************************************************************/
#define LDDK_USE_SYSCTL 1
#ifdef __KERNEL__
#include <linux/sysctl.h>

extern ctl_table Can_sysctl_table[];
extern ctl_table Can_sys_table[];



 /* ------ Global Definitions for version */

extern char version[];
#define SYSCTL_VERSION 1
 
 /* ------ Global Definitions for Chipset */

extern char Chipset[];
#define SYSCTL_CHIPSET 2
 
 /* ------ Global Definitions for IOModel */

extern char IOModel[];
#define SYSCTL_IOMODEL 3
 
 /* ------ Global Definitions for IRQ */

extern  int IRQ[];
#define SYSCTL_IRQ 4
 
 /* ------ Global Definitions for Base */

extern  unsigned int Base[];
#define SYSCTL_BASE 5
 
 /* ------ Global Definitions for Baud */

extern  int Baud[];
#define SYSCTL_BAUD 6
 
 /* ------ Global Definitions for AccCode */

extern  unsigned int AccCode[];
#define SYSCTL_ACCCODE 7
 
 /* ------ Global Definitions for AccMask */

extern  unsigned int AccMask[];
#define SYSCTL_ACCMASK 8
 
 /* ------ Global Definitions for Timeout */

extern  int Timeout[];
#define SYSCTL_TIMEOUT 9
 
 /* ------ Global Definitions for Outc */

extern  int Outc[];
#define SYSCTL_OUTC 10
 
 /* ------ Global Definitions for TxErr */

extern  int TxErr[];
#define SYSCTL_TXERR 11
 
 /* ------ Global Definitions for RxErr */

extern  int RxErr[];
#define SYSCTL_RXERR 12
 
 /* ------ Global Definitions for Overrun */

extern  int Overrun[];
#define SYSCTL_OVERRUN 13
 
 /* ------ Global Definitions for dbgMask */

extern unsigned int dbgMask;
#define SYSCTL_DBGMASK 14

 /* ------ Global Definitions for Test  */
extern  int Cnt1[];
#define SYSCTL_CNT1 15
extern  int Cnt2[];
#define SYSCTL_CNT2 16
 
 
#endif
/************************************************************************/



#ifndef CAN_MAJOR
#define CAN_MAJOR 91
#endif

extern int Can_errno;

#ifdef USE_LDDK_RETURN
#define LDDK_RETURN(arg) DBGout();return(arg)
#else
#define LDDK_RETURN(arg) return(arg)
#endif


/************************************************************************/
/* function prototypes */
/************************************************************************/
extern int CAN_ChipReset(int);
extern int CAN_SetTiming(int, int);
extern int CAN_StartChip(int);
extern int CAN_StopChip(int);
extern int CAN_SetMask(int, unsigned int, unsigned int);
extern int CAN_SetOMode(int,int);
extern int CAN_SetListenOnlyMode(int, int);
extern int CAN_SendMessage(int, canmsg_t *);
extern int CAN_GetMessage(int , canmsg_t *);
extern int CAN_SetBTR(int, int, int);

extern irqreturn_t CAN_Interrupt(int irq, void *unused, struct pt_regs *ptregs);

extern int CAN_VendorInit(int);

extern void register_systables(void);
extern void unregister_systables(void);

/* can_82c200funcs.c */
extern int CAN_ShowStat (int board);

/* can_mcf5282funcs.c */
void mcf_irqreset(void);
void mcf_irqsetup(void);

/* util.c */
extern int Can_FifoInit(int minor);
extern int Can_FilterCleanup(int minor);
extern int Can_FilterInit(int minor);
extern int Can_FilterMessage(int minor, unsigned message, unsigned enable);
extern int Can_FilterOnOff(int minor, unsigned on);
extern int Can_FilterSigNo(int minor, unsigned signo, unsigned signal);
extern int Can_FilterSignal(int minor, unsigned id, unsigned signal);
extern int Can_FilterTimestamp(int minor, unsigned message, unsigned stamp);
extern int Can_FreeIrq(int minor, int irq );
extern int Can_WaitInit(int minor);
extern void Can_StartTimer(unsigned long v);
extern void Can_StopTimer(void);
extern void Can_TimerInterrupt(unsigned long unused);
extern void can_dump(int minor);
extern void CAN_object_dump(int object);
extern void print_tty(const char *fmt, ...);

/* PCI support */
extern int pcimod_scan(void);

/* PC-Card support */

#ifdef CAN_INDEXED_PORT_IO
static inline unsigned Indexed_Inb(unsigned base,unsigned adr) {
  unsigned val;
  outb(adr,base);
  val=inb(base+1);
#ifdef IODEBUG
  printk("CANin: base: %x adr: %x, got: %x\n",base,adr,val);
#endif
  return val;
}
#endif

/************************************************************************/
/* hardware access functions or macros */
/************************************************************************/
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,6)
/* # define __iomem */
#endif
#if !defined(__iomem)
# define __iomem
#endif

#ifdef  CAN_PORT_IO
/* #error Intel port I/O access */
/* using port I/O with inb()/outb() for Intel architectures like 
   AT-CAN-MINI ISA board */

#ifdef IODEBUG
#  define CANout(bd,adr,v)	\
	(printk("Cout: (%x)=%x\n", (int)&((canregs_t *)Base[bd])->adr, v), \
		outb(v, (int) &((canregs_t *)Base[bd])->adr ))
#else
#  define CANout(bd,adr,v)	\
		(outb(v, (int) &((canregs_t *)Base[bd])->adr ))
#endif
#define CANin(bd,adr)		\
		(inb ((int) &((canregs_t *)Base[bd])->adr  ))
#define CANset(bd,adr,m)	\
	outb((inb((int) &((canregs_t *)Base[bd])->adr)) \
		| m ,(int) &((canregs_t *)Base[bd])->adr )
#define CANreset(bd,adr,m)	\
	outb((inb((int) &((canregs_t *)Base[bd])->adr)) \
		& ~m,(int) &((canregs_t *)Base[bd])->adr )
#define CANtest(bd,adr,m)	\
	(inb((int) &((canregs_t *)Base[bd])->adr  ) & m )

#endif 	/* CAN_PORT_IO */

#if !defined CAN_PORT_IO

#ifdef CAN_INDEXED_PORT_IO
/* #error Indexed Intel port I/O access */
/* using port I/O with indexed inb()/outb() for Intel architectures like 
   SSV TRM/816 DIL-NET-PC */

#ifdef IODEBUG
#define CANout(bd,adr,v) {\
        printk("CANout bd:%x base:%x reg:%x val:%x\n", \
                bd, (u32) Base[bd], \
		(u32) &regbase->adr,v); \
        outb((u32) &regbase->adr,(u32) Base[bd]);\
        outb(v,((u32) Base[bd])+1);\
  }
#else
#define CANout(bd,adr,v) {\
        outb((u32) &regbase->adr,(u32) Base[bd]);\
        outb(v,((u32) Base[bd])+1);\
}
#endif
#define CANin(bd,adr) \
        Indexed_Inb((u32) Base[bd],(u32) &regbase->adr)

#define CANset(bd,adr,m) {\
        unsigned val; \
        val=Indexed_Inb((u32) Base[bd],(u32) &regbase->adr);\
        outb((u32) &regbase->adr,(u32) Base[bd]);\
        outb(val | m,((u32) Base[bd])+1);\
}
#define CANreset(bd,adr,m) {\
        unsigned val; \
        val=Indexed_Inb((u32) Base[bd],(u32) &regbase->adr);\
        outb((u32) &regbase->adr,(u32) Base[bd]);\
        outb(val & ~m,((u32) Base[bd])+1);\
}
#define CANtest(bd,adr,m) \
        (Indexed_Inb((u32) Base[bd],(u32) &regbase->adr) & m)
#else

/* using memory acces with readb(), writeb() */
/* #error  memory I/O access */
/* #define can_base Base */
#ifdef IODEBUG
#  define CANout(bd,adr,v)	\
	(printk("Cout: (%x)=%x\n", (u32)&((canregs_t *)can_base[bd])->adr, v), \
		writeb(v, (u32) &((canregs_t *)can_base[bd])->adr ))

#define CANset(bd,adr,m)     do	{\
	unsigned char v;	\
        v = (readb((void __iomem *) &((canregs_t *)can_base[bd])->adr)); \
	printk("CANset %x |= %x\n", (v), (m)); \
	writeb( v | (m) , (u32) &((canregs_t *)can_base[bd])->adr ); \
	} while (0)

#define CANreset(bd,adr,m)	do {\
	unsigned char v; \
        v = (readb((u32) &((canregs_t *)can_base[bd])->adr)); \
	printk("CANreset %x &= ~%x\n", (v), (m)); \
	writeb( v & ~(m) , (u32) &((canregs_t *)can_base[bd])->adr ); \
	} while (0)

#else
   /* Memory Byte access */
#define CANout(bd,adr,v)	\
		(writeb(v, (void __iomem *) &((canregs_t *)can_base[bd])->adr ))
#define CANset(bd,adr,m)	\
	writeb((readb((void __iomem *) &((canregs_t *)can_base[bd])->adr)) \
		| (m) , (void __iomem *) &((canregs_t *)can_base[bd])->adr )
#define CANreset(bd,adr,m)	\
	writeb((readb((void __iomem *) &((canregs_t *)can_base[bd])->adr)) \
		& ~(m), (void __iomem *) &((canregs_t *)can_base[bd])->adr )
#endif
#define CANin(bd,adr)		\
		(readb ((void __iomem *) &((canregs_t *)can_base[bd])->adr  ))
#define CANtest(bd,adr,m)	\
	(readb((void __iomem *) &((canregs_t *)can_base[bd])->adr  ) & (m) )

   /* Memory word access */
#define CANoutw(bd,adr,v)	\
		(writew((v), (u32) &((canregs_t *)can_base[bd])->adr ))


#define CANoutwd(bd,adr,v)	\
	(printk("Cout: (%x)=%x\n", (u32)&((canregs_t *)can_base[bd])->adr, v), \
		writew((v), (u32) &((canregs_t *)can_base[bd])->adr ))


#define CANsetw(bd,adr,m)	\
	writew((readw((u32) &((canregs_t *)can_base[bd])->adr)) \
		| (m) , (u32) &((canregs_t *)can_base[bd])->adr )
#define CANresetw(bd,adr,m)	\
	writew((readw((u32) &((canregs_t *)can_base[bd])->adr)) \
		& ~(m), (u32) &((canregs_t *)can_base[bd])->adr )
#define CANinw(bd,adr)		\
		(readw ((u32) &((canregs_t *)can_base[bd])->adr  ))
#define CANinwd(bd,adr)		\
	(printk("Cin: (%x)\n", (u32)&((canregs_t *)can_base[bd])->adr), \
		readw ((u32) &((canregs_t *)can_base[bd])->adr  ))
#define CANtestw(bd,adr,m)	\
	(readw((u32) &((canregs_t *)can_base[bd])->adr  ) & (m) )


   /* Memory long word access */
#define CANoutl(bd,adr,v)	\
		(writel(v, (u32) &((canregs_t *)can_base[bd])->adr ))
#define CANsetl(bd,adr,m)	\
	writel((readl((u32) &((canregs_t *)can_base[bd])->adr)) \
		| (m) , (u32) &((canregs_t *)can_base[bd])->adr )
#define CANresetl(bd,adr,m)	\
	writel((readl((u32) &((canregs_t *)can_base[bd])->adr)) \
		& ~(m), (u32) &((canregs_t *)can_base[bd])->adr )
#define CANinl(bd,adr)		\
		(readl ((u32) &((canregs_t *)can_base[bd])->adr  ))
#define CANtestl(bd,adr,m)	\
	(readl((u32) &((canregs_t *)can_base[bd])->adr  ) & (m) )


#endif

#endif 		/* ! CAN_PORT_IO */
/*________________________E_O_F_____________________________________________*/


#if 0
/*
There is a special access mode for the 82527 CAN controller
called fast register access.
This mode is sometimes used instead of normal Mem-Read/Write
and substitutes  MEM_In/MEM_Out

*/

uint8 MEM_In (unsigned long  adr ) { 
#if IODEBUG
        int ret = readb(adr);
        printk("MIn: 0x%x=0x%x\n", adr, ret);
        return ret;
#else
	SLOW_DOWN_IO;	SLOW_DOWN_IO;
	return readb(adr);
#endif
}

uint8 fastMEM_In (unsigned long  adr ) {
        /* Fast access:
         * first read desired register,
         * after that read register 4
         */
	int ret = readb(adr);
        if((adr & 0x000000FF) == 0x02) {
        	return ret;
	}
	/* 250 ns delay, SLOW_DOWN_IO is empty on ELIMA */
	asm volatile("nop;nop;nop;nop");
	asm volatile("nop;nop;nop;nop");
	asm volatile("nop;nop;nop;nop");
	asm volatile("nop;nop;nop;nop");
	ret = readb((adr & 0xFFFFFF00) + 4);
#if IODEBUG
        printk("MfIn: 0x%x=0x%x\n", adr, ret);
#endif
        return ret;
}

void MEM_Out(uint8 v, unsigned long adr ) {
#if IODEBUG
        printk("MOut: 0x%x->0x%x\n", v, adr);
#endif
	SLOW_DOWN_IO;
        writeb(v, adr);
	SLOW_DOWN_IO; 
#if defined(CONFIG_PPC)
	/* 250 ns delay, SLOW_DOWN_IO is empty on ELIMA */
	asm volatile("nop;nop;nop;nop");
	asm volatile("nop;nop;nop;nop");
	asm volatile("nop;nop;nop;nop");
	asm volatile("nop;nop;nop;nop");
#endif
}

#endif







