/*
 * TE410P  Quad-T1/E1 PCI Driver version 0.1, 12/16/02
 *
 * Written by Mark Spencer <markster@digium.com>
 * Based on previous works, designs, and archetectures conceived and
 * written by Jim Dixon <jim@lambdatel.com>.
 *
 * Copyright (C) 2001 Jim Dixon / Zapata Telephony.
 * Copyright (C) 2001-2005, Digium, Inc.
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

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#ifdef STANDALONE_ZAPATA
#include "zaptel.h"
#else
#include <linux/zaptel.h>
#endif
#ifdef LINUX26
#include <linux/moduleparam.h>
#endif
#include "wct4xxp.h"

/*
 * Tasklets provide better system interactive response at the cost of the
 * possibility of losing a frame of data at very infrequent intervals.  If
 * you are more concerned with the performance of your machine, enable the
 * tasklets.  If you are strict about absolutely no drops, then do not enable
 * tasklets.
 */

/* #define ENABLE_TASKLETS */


/* Work queues are a way to better distribute load on SMP systems */
#ifdef LINUX26
#define ENABLE_WORKQUEUES
#endif

/* Enable prefetching may help performance */
#define ENABLE_PREFETCH

/* Support first generation cards? */
#define SUPPORT_GEN1 

/* Define to get more attention-grabbing but slightly more I/O using
   alarm status */
#define FANCY_ALARM

/* Define to support Digium Voice Processing Module expansion card */
#define VPM_SUPPORT

#define DEBUG_MAIN 		(1 << 0)
#define DEBUG_DTMF 		(1 << 1)
#define DEBUG_REGS 		(1 << 2)
#define DEBUG_TSI  		(1 << 3)
#define DEBUG_ECHOCAN 	(1 << 4)
#define DEBUG_RBS 		(1 << 5)
#define DEBUG_FRAMER		(1 << 6)

#ifdef ENABLE_WORKQUEUES
#include <linux/cpumask.h>

/* XXX UGLY!!!! XXX  We have to access the direct structures of the workqueue which
  are only defined within workqueue.c because they don't give us a routine to allow us
  to nail a work to a particular thread of the CPU.  Nailing to threads gives us substantially
  higher scalability in multi-CPU environments though! */

/*
 * The per-CPU workqueue (if single thread, we always use cpu 0's).
 *
 * The sequence counters are for flush_scheduled_work().  It wants to wait
 * until until all currently-scheduled works are completed, but it doesn't
 * want to be livelocked by new, incoming ones.  So it waits until
 * remove_sequence is >= the insert_sequence which pertained when
 * flush_scheduled_work() was called.
 */
 
struct cpu_workqueue_struct {

	spinlock_t lock;

	long remove_sequence;	/* Least-recently added (next to run) */
	long insert_sequence;	/* Next to add */

	struct list_head worklist;
	wait_queue_head_t more_work;
	wait_queue_head_t work_done;

	struct workqueue_struct *wq;
	task_t *thread;

	int run_depth;		/* Detect run_workqueue() recursion depth */
} ____cacheline_aligned;

/*
 * The externally visible workqueue abstraction is an array of
 * per-CPU workqueues:
 */
struct workqueue_struct {
	struct cpu_workqueue_struct cpu_wq[NR_CPUS];
	const char *name;
	struct list_head list; 	/* Empty if single thread */
};

/* Preempt must be disabled. */
static void __t4_queue_work(struct cpu_workqueue_struct *cwq,
			 struct work_struct *work)
{
	unsigned long flags;

	spin_lock_irqsave(&cwq->lock, flags);
	work->wq_data = cwq;
	list_add_tail(&work->entry, &cwq->worklist);
	cwq->insert_sequence++;
	wake_up(&cwq->more_work);
	spin_unlock_irqrestore(&cwq->lock, flags);
}

/*
 * Queue work on a workqueue. Return non-zero if it was successfully
 * added.
 *
 * We queue the work to the CPU it was submitted, but there is no
 * guarantee that it will be processed by that CPU.
 */
static inline int t4_queue_work(struct workqueue_struct *wq, struct work_struct *work, int cpu)
{
	int ret = 0;

	if (!test_and_set_bit(0, &work->pending)) {
		BUG_ON(!list_empty(&work->entry));
		__t4_queue_work(wq->cpu_wq + cpu, work);
		ret = 1;
	}
	return ret;
}

#endif

static int debug=DEBUG_ECHOCAN;
static int timingcable;
static int highestorder;
static int t1e1override = -1;
static int j1mode = 0;
static int loopback = 0;
static int alarmdebounce = 0;
#ifdef VPM_SUPPORT
static int vpmsupport = 1;
#endif
static int noburst = 0;
static int debugslips = 0;
static int polling = 0;

#ifdef FANCY_ALARM
static int altab[] = {
0, 0, 0, 1, 2, 3, 4, 6, 8, 9, 11, 13, 16, 18, 20, 22, 24, 25, 27, 28, 29, 30, 31, 31, 32, 31, 31, 30, 29, 28, 27, 25, 23, 22, 20, 18, 16, 13, 11, 9, 8, 6, 4, 3, 2, 1, 0, 0, 
};
#endif

#define MAX_SPANS 16

#define FLAG_STARTED (1 << 0)
#define FLAG_NMF (1 << 1)
#define FLAG_SENDINGYELLOW (1 << 2)


#define	TYPE_T1	1		/* is a T1 card */
#define	TYPE_E1	2		/* is an E1 card */
#define TYPE_J1 3		/* is a running J1 */

#define FLAG_2NDGEN  (1 << 3)
#define FLAG_2PORT   (1 << 4)

#define CANARY 0xc0de

struct devtype {
	char *desc;
	unsigned int flags;
};

static struct devtype wct4xxp = { "Wildcard TE410P/TE405P (1st Gen)", 0 };
static struct devtype wct410p2 = { "Wildcard TE410P (2nd Gen)", FLAG_2NDGEN };
static struct devtype wct405p2 = { "Wildcard TE405P (2nd Gen)", FLAG_2NDGEN };
static struct devtype wct205 = { "Wildcard TE205P ", FLAG_2NDGEN | FLAG_2PORT };
static struct devtype wct210 = { "Wildcard TE210P ", FLAG_2NDGEN | FLAG_2PORT };
	

static int inirq = 0;

struct t4;

struct t4_span {
	struct t4 *owner;
	unsigned int *writechunk;					/* Double-word aligned write memory */
	unsigned int *readchunk;					/* Double-word aligned read memory */
	int spantype;		/* card type, T1 or E1 or J1 */
	int sync;
	int psync;
	int alarmtimer;
	int redalarms;
	int notclear;
	int alarmcount;
	int spanflags;
	int syncpos;
#ifdef SUPPORT_GEN1
	int e1check;			/* E1 check */
#endif
	struct zt_span span;
	unsigned char txsigs[16];	/* Transmit sigs */
	int loopupcnt;
	int loopdowncnt;
#ifdef SUPPORT_GEN1
	unsigned char ec_chunk1[31][ZT_CHUNKSIZE]; /* first EC chunk buffer */
	unsigned char ec_chunk2[31][ZT_CHUNKSIZE]; /* second EC chunk buffer */
#endif
	int irqmisses;
#ifdef VPM_SUPPORT
	unsigned int dtmfactive;
	unsigned int dtmfmask;
	unsigned int dtmfmutemask;
	short dtmfenergy[31];
	short dtmfdigit[31];
#endif
#ifdef ENABLE_WORKQUEUES
	struct work_struct swork;
#endif	
	struct zt_chan chans[0];		/* Individual channels */
};

struct t4 {
	/* This structure exists one per card */
	struct pci_dev *dev;		/* Pointer to PCI device */
	unsigned int intcount;
	int num;			/* Which card we are */
	int t1e1;			/* T1/E1 select pins */
	int globalconfig;	/* Whether global setup has been done */
	int syncsrc;			/* active sync source */
	struct t4_span *tspans[4];	/* Individual spans */
	int numspans;			/* Number of spans on the card */
#ifdef VPM_SUPPORT
	int vpm;
#endif	

	int blinktimer;
#ifdef FANCY_ALARM
	int alarmpos;
#endif
	int irq;			/* IRQ used by device */
	int order;			/* Order */
	int flags;			/* Device flags */
	int master;				/* Are we master */
	int ledreg;				/* LED Register */
	unsigned int dmactrl;
	int e1recover;			/* E1 recovery timer */
	dma_addr_t 	readdma;
	dma_addr_t	writedma;
	unsigned long memaddr;		/* Base address of card */
	unsigned long memlen;
	volatile unsigned int *membase;	/* Base address of card */
	int spansstarted;		/* number of spans started */
	/* spinlock_t lock; */		/* lock context */
	spinlock_t reglock;		/* lock register access */
	volatile unsigned int *writechunk;					/* Double-word aligned write memory */
	volatile unsigned int *readchunk;					/* Double-word aligned read memory */
	unsigned short canary;
#ifdef ENABLE_WORKQUEUES
	atomic_t worklist;
	struct workqueue_struct *workq;
#else
#ifdef ENABLE_TASKLETS
	int taskletrun;
	int taskletsched;
	int taskletpending;
	int taskletexec;
	int txerrors;
	struct tasklet_struct t4_tlet;
#endif
#endif
	unsigned int passno;	/* number of interrupt passes */
	char *variety;
	int last0;		/* for detecting double-missed IRQ */
	int checktiming;	/* Set >0 to cause the timing source to be checked */
};

#define T4_VPM_PRESENT (1 << 28)


#ifdef VPM_SUPPORT
static void t4_vpm_init(struct t4 *wc);
#endif
static void __set_clear(struct t4 *wc, int span);
static int t4_startup(struct zt_span *span);
static int t4_shutdown(struct zt_span *span);
static int t4_rbsbits(struct zt_chan *chan, int bits);
static int t4_maint(struct zt_span *span, int cmd);
#ifdef SUPPORT_GEN1
static int t4_reset_dma(struct t4 *wc);
#endif
static int t4_ioctl(struct zt_chan *chan, unsigned int cmd, unsigned long data);
static void t4_tsi_assign(struct t4 *wc, int fromspan, int fromchan, int tospan, int tochan);
static void t4_tsi_unassign(struct t4 *wc, int tospan, int tochan);
static void __t4_set_timing_source(struct t4 *wc, int unit);
static void __t4_check_alarms(struct t4 *wc, int span);
static void __t4_check_sigbits(struct t4 *wc, int span);

#define WC_RDADDR	0
#define WC_WRADDR	1
#define WC_COUNT	2
#define WC_DMACTRL	3	
#define WC_INTR		4
/* #define WC_GPIO		5 */
#define WC_VERSION	6
#define WC_LEDS		7
#define WC_ACTIVATE	(1 << 12)
#define WC_GPIOCTL	8
#define WC_GPIO		9
#define WC_LADDR	10
#define WC_LDATA		11
#define WC_LREAD			(1 << 15)
#define WC_LWRITE		(1 << 16)

#define WC_OFF    (0)
#define WC_RED    (1)
#define WC_GREEN  (2)
#define WC_YELLOW (3)

#define MAX_T4_CARDS 64

#ifdef ENABLE_TASKLETS
static void t4_tasklet(unsigned long data);
#endif

static struct t4 *cards[MAX_T4_CARDS];


#define MAX_TDM_CHAN 32
#define MAX_DTMF_DET 16

static inline void __t4_pci_out(struct t4 *wc, const unsigned int addr, const unsigned int value)
{
	unsigned int tmp;
	wc->membase[addr] = cpu_to_le32(value);
#if 1
	tmp = le32_to_cpu(wc->membase[addr]);
	if ((value != tmp) && (addr != WC_LEDS) && (addr != WC_LDATA) &&
		(addr != WC_GPIO) && (addr != WC_INTR))
		printk("Tried to load %08x into %08x, but got %08x instead\n", value, addr, tmp);
#endif		
}

static inline unsigned int __t4_pci_in(struct t4 *wc, const unsigned int addr)
{
	return le32_to_cpu(wc->membase[addr]);
}

static inline void t4_pci_out(struct t4 *wc, const unsigned int addr, const unsigned int value)
{
	unsigned long flags;
	spin_lock_irqsave(&wc->reglock, flags);
	__t4_pci_out(wc, addr, value);
	spin_unlock_irqrestore(&wc->reglock, flags);
}

static inline void __t4_set_led(struct t4 *wc, int span, int color)
{
	int oldreg = wc->ledreg;
	wc->ledreg &= ~(0x3 << (span << 1));
	wc->ledreg |= (color << (span << 1));
	if (oldreg != wc->ledreg)
		__t4_pci_out(wc, WC_LEDS, wc->ledreg);
}

static inline void t4_activate(struct t4 *wc)
{
	wc->ledreg |= WC_ACTIVATE;
	t4_pci_out(wc, WC_LEDS, wc->ledreg);
}

static inline unsigned int t4_pci_in(struct t4 *wc, const unsigned int addr)
{
	unsigned int ret;
	unsigned long flags;
	
	spin_lock_irqsave(&wc->reglock, flags);
	ret = __t4_pci_in(wc, addr);
	spin_unlock_irqrestore(&wc->reglock, flags);
	return ret;
}

static inline unsigned int __t4_framer_in(struct t4 *wc, int unit, const unsigned int addr)
{
	unsigned int ret;
	unit &= 0x3;
	__t4_pci_out(wc, WC_LADDR, (unit << 8) | (addr & 0xff));
	__t4_pci_out(wc, WC_LADDR, (unit << 8) | (addr & 0xff) | ( 1 << 10) | WC_LREAD);
	ret = __t4_pci_in(wc, WC_LDATA);
	__t4_pci_out(wc, WC_LADDR, 0);
	return ret & 0xff;
}

static inline unsigned int t4_framer_in(struct t4 *wc, int unit, const unsigned int addr)
{
	unsigned long flags;
	unsigned int ret;
	spin_lock_irqsave(&wc->reglock, flags);
	ret = __t4_framer_in(wc, unit, addr);
	spin_unlock_irqrestore(&wc->reglock, flags);
	return ret;

}

static inline void __t4_framer_out(struct t4 *wc, int unit, const unsigned int addr, const unsigned int value)
{
	unit &= 0x3;
	if (debug & DEBUG_REGS)
		printk("Writing %02x to address %02x of unit %d\n", value, addr, unit);
	__t4_pci_out(wc, WC_LADDR, (unit << 8) | (addr & 0xff));
	__t4_pci_out(wc, WC_LDATA, value);
	__t4_pci_out(wc, WC_LADDR, (unit << 8) | (addr & 0xff) | (1 << 10));
	__t4_pci_out(wc, WC_LADDR, (unit << 8) | (addr & 0xff) | (1 << 10) | WC_LWRITE);
	__t4_pci_out(wc, WC_LADDR, (unit << 8) | (addr & 0xff) | (1 << 10));
	__t4_pci_out(wc, WC_LADDR, (unit << 8) | (addr & 0xff));	
	__t4_pci_out(wc, WC_LADDR, 0);
	if (debug & DEBUG_REGS) printk("Write complete\n");
#if 0
	{ unsigned int tmp;
	tmp = t4_framer_in(wc, unit, addr);
	if (tmp != value) {
		printk("Expected %d from unit %d register %d but got %d instead\n", value, unit, addr, tmp);
	} }
#endif	
}

static inline void t4_framer_out(struct t4 *wc, int unit, const unsigned int addr, const unsigned int value)
{
	unsigned long flags;
	spin_lock_irqsave(&wc->reglock, flags);
	__t4_framer_out(wc, unit, addr, value);
	spin_unlock_irqrestore(&wc->reglock, flags);
}

#ifdef VPM_SUPPORT

static inline void wait_a_little(void)
{
	unsigned long newjiffies=jiffies+2;
	while(jiffies < newjiffies);
}

static inline unsigned int __t4_vpm_in(struct t4 *wc, int unit, const unsigned int addr)
{
	unsigned int ret;
	unit &= 0x7;
	__t4_pci_out(wc, WC_LADDR, (addr & 0x1ff) | ( unit << 12));
	__t4_pci_out(wc, WC_LADDR, (addr & 0x1ff) | ( unit << 12) | (1 << 11) | WC_LREAD);
	ret = __t4_pci_in(wc, WC_LDATA);
	__t4_pci_out(wc, WC_LADDR, 0);
	return ret & 0xff;
}

static inline unsigned int t4_vpm_in(struct t4 *wc, int unit, const unsigned int addr)
{
	unsigned long flags;
	unsigned int ret;
	spin_lock_irqsave(&wc->reglock, flags);
	ret = __t4_vpm_in(wc, unit, addr);
	spin_unlock_irqrestore(&wc->reglock, flags);
	return ret;
}

static inline void __t4_vpm_out(struct t4 *wc, int unit, const unsigned int addr, const unsigned int value)
{
	unit &= 0x7;
	if (debug & DEBUG_REGS)
		printk("Writing %02x to address %02x of ec unit %d\n", value, addr, unit);
	__t4_pci_out(wc, WC_LADDR, (addr & 0xff));
	__t4_pci_out(wc, WC_LDATA, value);
	__t4_pci_out(wc, WC_LADDR, (unit << 12) | (addr & 0x1ff) | (1 << 11));
	__t4_pci_out(wc, WC_LADDR, (unit << 12) | (addr & 0x1ff) | (1 << 11) | WC_LWRITE);
	__t4_pci_out(wc, WC_LADDR, (unit << 12) | (addr & 0x1ff) | (1 << 11));
	__t4_pci_out(wc, WC_LADDR, (unit << 12) | (addr & 0x1ff));	
	__t4_pci_out(wc, WC_LADDR, 0);
	if (debug & DEBUG_REGS) printk("Write complete\n");

      
#if 0
	{ unsigned int tmp;
	tmp = t4_vpm_in(wc, unit, addr);
	if (tmp != value) {
		printk("Expected %d from unit %d echo register %d but got %d instead\n", value, unit, addr, tmp);
	} }
#endif
}

static inline void t4_vpm_out(struct t4 *wc, int unit, const unsigned int addr, const unsigned int value)
{
	unsigned long flags;
	spin_lock_irqsave(&wc->reglock, flags);
	__t4_vpm_out(wc, unit, addr, value);
	spin_unlock_irqrestore(&wc->reglock, flags);
}

static void __t4_check_vpm(struct t4 *wc, unsigned int newio)
{
	unsigned int digit, regval = 0;
	int x, i;
	short energy;
	static unsigned int lastio = 0;
	struct t4_span *ts;

	if (debug && (newio != lastio)) 
		printk("Last was %08x, new is %08x\n", lastio, newio);

	lastio = newio;
 
	for(x = 0; x < 8; x++) {
		if (newio & (1 << (7 - x)))
			continue;
		ts = wc->tspans[x%4];
		/* Start of DTMF detection process */	
		regval = __t4_vpm_in(wc, x, 0xb8);
		__t4_vpm_out(wc, x, 0xb8, regval); /* Write 1 to clear */
		regval = regval << 8;
		regval |= __t4_vpm_in(wc, x, 0xb9);
		__t4_vpm_out(wc, x, 0xb9, regval & 0xff);

		for(i = 0; (i < MAX_DTMF_DET) && regval; i++) {
			if(regval & 0x0001) {
				int channel = (i << 1) + (x >> 2);
				int base = channel - 1;
				if (!wc->t1e1)
					base -= 4;
				digit = __t4_vpm_in(wc, x, 0xa8 + i);
				if (digit < 10) 
					digit += '0'; 
				else if (digit < 0xe) 
					digit += 'A' - 0xe; 
				else if (digit == 0xe) 
					digit = '*';
				else if (digit == 0xf) 
					digit = '#';
				energy = __t4_vpm_in(wc, x, 0x58 + channel);
				energy = ZT_XLAW(energy, ts->chans);
				ts->dtmfactive |= (1 << base);
				ts->dtmfenergy[base] = energy;
				if (ts->dtmfdigit[base]) {
					if (ts->dtmfmask & (1 << base))
						zt_qevent_lock(&ts->span.chans[base], (ZT_EVENT_DTMFUP | ts->dtmfdigit[base]));
				}
				ts->dtmfdigit[base] = digit;
				if (ts->dtmfdigit[base]) {
					if (ts->dtmfmask & (1 << base))
						zt_qevent_lock(&ts->span.chans[base], (ZT_EVENT_DTMFUP | ts->dtmfdigit[base]));
				}
				if (ts->dtmfmask & (1 << base))
					zt_qevent_lock(&ts->span.chans[base], (ZT_EVENT_DTMFDOWN | digit));
				if (ts->dtmfmutemask & (1 << base)) {
					/* Mute active receive buffer*/
					unsigned long flags;
					struct zt_chan *chan = &ts->span.chans[base];
					int y;
					spin_lock_irqsave(&chan->lock, flags);
					for (y=0;y<chan->numbufs;y++) {
						if (chan->readidx[y]) 
							memset(chan->readbuf[chan->inreadbuf], ZT_XLAW(0, chan), chan->readidx[y]);
					}
					spin_unlock_irqrestore(&chan->lock, flags);
				}
				if (debug)
					printk("Digit Seen: %d, Span: %d, channel: %d, energy: %02x, 'channel %d' chip %d\n", digit, x % 4, base + 1, energy, channel, x);
				
			}
			regval = regval >> 1;
		}
	}
}
#endif


static void __set_clear(struct t4 *wc, int span)
{
	int i,j;
	int oldnotclear;
	unsigned short val=0;
	struct t4_span *ts = wc->tspans[span];

	oldnotclear = ts->notclear;
	if (ts->spantype == TYPE_T1) {
		for (i=0;i<24;i++) {
			j = (i/8);
			if (ts->span.chans[i].flags & ZT_FLAG_CLEAR) {
				val |= 1 << (7 - (i % 8));
				ts->notclear &= ~(1 << i);
			} else
				ts->notclear |= (1 << i);
			if ((i % 8)==7) {
				if (debug)
					printk("Putting %d in register %02x on span %d\n",
				       val, 0x2f + j, span + 1);
				__t4_framer_out(wc, span, 0x2f + j, val);
				val = 0;
			}
		}
	} else {
		for (i=0;i<31;i++) {
			if (ts->span.chans[i].flags & ZT_FLAG_CLEAR)
				ts->notclear &= ~(1 << i);
			else 
				ts->notclear |= (1 << i);
		}
	}
	if (ts->notclear != oldnotclear) {
		unsigned char reg;
		reg = __t4_framer_in(wc, span, 0x14);
		if (ts->notclear)
			reg &= ~0x08;
		else
			reg |= 0x08;
		__t4_framer_out(wc, span, 0x14, reg);
	}
}

#if 0
static void set_clear(struct t4 *wc, int span)
{
	unsigned long flags;
	spin_lock_irqsave(&wc->reglock, flags);
	__set_clear(wc, span);
	spin_unlock_irqrestore(&wc->reglock, flags);
}
#endif

static int t4_dacs(struct zt_chan *dst, struct zt_chan *src)
{
	struct t4 *wc;
	struct t4_span *ts;
	wc = dst->pvt;
	ts = wc->tspans[dst->span->offset];
	if (src && (src->pvt != dst->pvt)) {
		if (ts->spanflags & FLAG_2NDGEN)
			t4_tsi_unassign(wc, dst->span->offset, dst->chanpos);
		wc = src->pvt;
		if (ts->spanflags & FLAG_2NDGEN)
			t4_tsi_unassign(wc, src->span->offset, src->chanpos);
		if (debug)
			printk("Unassigning %d/%d by default and...\n", src->span->offset, src->chanpos);
		if (debug)
			printk("Unassigning %d/%d by default\n", dst->span->offset, dst->chanpos);
		return -1;
	}
	if (src) {
		t4_tsi_assign(wc, src->span->offset, src->chanpos, dst->span->offset, dst->chanpos);
		if (debug)
			printk("Assigning channel %d/%d -> %d/%d!\n", src->span->offset, src->chanpos, dst->span->offset, dst->chanpos);
	} else {
		t4_tsi_unassign(wc, dst->span->offset, dst->chanpos);
		if (debug)
			printk("Unassigning channel %d/%d!\n", dst->span->offset, dst->chanpos);
	}
	return 0;
}

#ifdef VPM_SUPPORT
static int t4_echocan(struct zt_chan *chan, int eclen)
{
	struct t4 *wc = chan->pvt;
	int channel;
	int unit;
	if (!wc->vpm)
		return -ENODEV;
	unit = chan->span->offset;
	if (wc->t1e1)
		channel = chan->chanpos;
	else
		channel = chan->chanpos + 4;
	if ((channel & 1))
		unit += 4;
	if(debug & DEBUG_ECHOCAN) 
		printk("echocan: Card is %d, Channel is %d, Span is %d, unit is %d, unit offset is %d length %d\n", 
			wc->num, chan->chanpos, chan->span->offset, unit, channel, eclen);
	if (eclen)
		t4_vpm_out(wc,unit,channel,0x3e);
	else
		t4_vpm_out(wc,unit,channel,0x01);
	return 0;
}
#endif

static int t4_ioctl(struct zt_chan *chan, unsigned int cmd, unsigned long data)
{
	struct t4_regs regs;
	int x;
	struct t4 *wc = chan->pvt;
#ifdef VPM_SUPPORT
	int j;
	struct t4_span *ts = wc->tspans[chan->span->offset];
#endif

	switch(cmd) {
	case WCT4_GET_REGS:
		wc = chan->pvt;
		for (x=0;x<NUM_PCI;x++)
			regs.pci[x] = t4_pci_in(wc, x);
		for (x=0;x<NUM_REGS;x++)
			regs.regs[x] = t4_framer_in(wc, chan->span->offset, x);
		if (copy_to_user((struct t4_regs *)data, &regs, sizeof(regs)))
			return -EFAULT;
		{
			static unsigned char filldata = 0;
			memset(wc->tspans[0]->writechunk, filldata, ZT_CHUNKSIZE * 32);
		}
		break;
#ifdef VPM_SUPPORT
	case ZT_TONEDETECT:
		if (get_user(j, (int *)data))
			return -EFAULT;
		wc = chan->pvt;
		if (!wc->vpm)
			return -ENOSYS;
		if (j & ZT_TONEDETECT_ON)
			ts->dtmfmask |= (1 << (chan->chanpos - 1));
		else
			ts->dtmfmask &= ~(1 << (chan->chanpos - 1));
		if (j & ZT_TONEDETECT_MUTE)
			ts->dtmfmutemask |= (1 << (chan->chanpos - 1));
		else
			ts->dtmfmutemask &= ~(1 << (chan->chanpos - 1));
		return 0;
#endif
	default:
		return -ENOTTY;
	}
	return 0;
}

static int t4_maint(struct zt_span *span, int cmd)
{
	struct t4_span *ts = span->pvt;
	struct t4 *wc = ts->owner;

	if (ts->spantype == TYPE_E1) {
		switch(cmd) {
		case ZT_MAINT_NONE:
			printk("XXX Turn off local and remote loops E1 XXX\n");
			break;
		case ZT_MAINT_LOCALLOOP:
			printk("XXX Turn on local loopback E1 XXX\n");
			break;
		case ZT_MAINT_REMOTELOOP:
			printk("XXX Turn on remote loopback E1 XXX\n");
			break;
		case ZT_MAINT_LOOPUP:
			printk("XXX Send loopup code E1 XXX\n");
			break;
		case ZT_MAINT_LOOPDOWN:
			printk("XXX Send loopdown code E1 XXX\n");
			break;
		case ZT_MAINT_LOOPSTOP:
			printk("XXX Stop sending loop codes E1 XXX\n");
			break;
		default:
			printk("TE%dXXP: Unknown E1 maint command: %d\n", wc->numspans, cmd);
			break;
		}
	} else {
		switch(cmd) {
	    case ZT_MAINT_NONE:
			printk("XXX Turn off local and remote loops T1 XXX\n");
			break;
	    case ZT_MAINT_LOCALLOOP:
			printk("XXX Turn on local loop and no remote loop XXX\n");
			break;
	    case ZT_MAINT_REMOTELOOP:
			printk("XXX Turn on remote loopup XXX\n");
			break;
	    case ZT_MAINT_LOOPUP:
			t4_framer_out(wc, span->offset, 0x21, 0x50);	/* FMR5: Nothing but RBS mode */
			break;
	    case ZT_MAINT_LOOPDOWN:
			t4_framer_out(wc, span->offset, 0x21, 0x60);	/* FMR5: Nothing but RBS mode */
			break;
	    case ZT_MAINT_LOOPSTOP:
			t4_framer_out(wc, span->offset, 0x21, 0x40);	/* FMR5: Nothing but RBS mode */
			break;
	    default:
			printk("TE%dXXP: Unknown T1 maint command: %d\n", wc->numspans, cmd);
			break;
	   }
    }
	return 0;
}

static int t4_rbsbits(struct zt_chan *chan, int bits)
{
	u_char m,c;
	int k,n,b;
	struct t4 *wc = chan->pvt;
	struct t4_span *ts = wc->tspans[chan->span->offset];
	unsigned long flags;
	
	if(debug & DEBUG_RBS) printk("Setting bits to %d on channel %s\n", bits, chan->name);
	spin_lock_irqsave(&wc->reglock, flags);	
	k = chan->span->offset;
	if (ts->spantype == TYPE_E1) { /* do it E1 way */
		if (chan->chanpos == 16) {
			spin_unlock_irqrestore(&wc->reglock, flags);
			return 0;
		}
		n = chan->chanpos - 1;
		if (chan->chanpos > 15) n--;
		b = (n % 15);
		c = ts->txsigs[b];
		m = (n / 15) << 2; /* nibble selector */
		c &= (0xf << m); /* keep the other nibble */
		c |= (bits & 0xf) << (4 - m); /* put our new nibble here */
		ts->txsigs[b] = c;
		  /* output them to the chip */
		__t4_framer_out(wc,k,0x71 + b,c); 
	} else if (ts->span.lineconfig & ZT_CONFIG_D4) {
		n = chan->chanpos - 1;
		b = (n/4);
		c = ts->txsigs[b];
		m = ((3 - (n % 4)) << 1); /* nibble selector */
		c &= ~(0x3 << m); /* keep the other nibble */
		c |= ((bits >> 2) & 0x3) << m; /* put our new nibble here */
		ts->txsigs[b] = c;
		  /* output them to the chip */
		__t4_framer_out(wc,k,0x70 + b,c); 
		__t4_framer_out(wc,k,0x70 + b + 6,c); 
	} else if (ts->span.lineconfig & ZT_CONFIG_ESF) {
		n = chan->chanpos - 1;
		b = (n/2);
		c = ts->txsigs[b];
		m = ((n % 2) << 2); /* nibble selector */
		c &= (0xf << m); /* keep the other nibble */
		c |= (bits & 0xf) << (4 - m); /* put our new nibble here */
		ts->txsigs[b] = c;
		  /* output them to the chip */
		__t4_framer_out(wc,k,0x70 + b,c); 
	} 
	spin_unlock_irqrestore(&wc->reglock, flags);
	if (debug & DEBUG_RBS)
		printk("Finished setting RBS bits\n");
	return 0;
}

static int t4_shutdown(struct zt_span *span)
{
	int tspan;
	int wasrunning;
	unsigned long flags;
	struct t4_span *ts = span->pvt;
	struct t4 *wc = ts->owner;

	tspan = span->offset + 1;
	if (tspan < 0) {
		printk("T%dXXP: Span '%d' isn't us?\n", wc->numspans, span->spanno);
		return -1;
	}

	spin_lock_irqsave(&wc->reglock, flags);
	wasrunning = span->flags & ZT_FLAG_RUNNING;

	span->flags &= ~ZT_FLAG_RUNNING;
	if (wasrunning)
		wc->spansstarted--;
	__t4_set_led(wc, span->offset, WC_OFF);
	if (((wc->numspans == 4) && 
	    (!(wc->tspans[0]->span.flags & ZT_FLAG_RUNNING)) &&
	    (!(wc->tspans[1]->span.flags & ZT_FLAG_RUNNING)) &&
	    (!(wc->tspans[2]->span.flags & ZT_FLAG_RUNNING)) &&
	    (!(wc->tspans[3]->span.flags & ZT_FLAG_RUNNING)))
	    			|| 
	    ((wc->numspans == 2) && 
	    (!(wc->tspans[0]->span.flags & ZT_FLAG_RUNNING)) &&
	    (!(wc->tspans[1]->span.flags & ZT_FLAG_RUNNING)))) {
		/* No longer in use, disable interrupts */
		printk("TE%dXXP: Disabling interrupts since there are no active spans\n", wc->numspans);
		wc->dmactrl = 0x0;
		__t4_pci_out(wc, WC_DMACTRL, 0x00000000);
		/* Acknowledge any pending interrupts */
		__t4_pci_out(wc, WC_INTR, 0x00000000);
		__t4_set_timing_source(wc,4);
	} else wc->checktiming = 1;
	spin_unlock_irqrestore(&wc->reglock, flags);
	if (debug & DEBUG_MAIN)
		printk("Span %d (%s) shutdown\n", span->spanno, span->name);
	return 0;
}

static int t4_spanconfig(struct zt_span *span, struct zt_lineconfig *lc)
{
	int i;
	struct t4_span *ts = span->pvt;
	struct t4 *wc = ts->owner;

	printk("About to enter spanconfig!\n");
	if (debug & DEBUG_MAIN)
		printk("TE%dXXP: Configuring span %d\n", wc->numspans, span->spanno);
	/* XXX We assume lineconfig is okay and shouldn't XXX */	
	span->lineconfig = lc->lineconfig;
	span->txlevel = lc->lbo;
	span->rxlevel = 0;
	if (lc->sync < 0)
		lc->sync = 0;
	if (lc->sync > 4)
		lc->sync = 0;
	
	/* remove this span number from the current sync sources, if there */
	for(i = 0; i < wc->numspans; i++) {
		if (wc->tspans[i]->sync == span->spanno) {
			wc->tspans[i]->sync = 0;
			wc->tspans[i]->psync = 0;
		}
	}
	wc->tspans[span->offset]->syncpos = lc->sync;
	/* if a sync src, put it in proper place */
	if (lc->sync) {
		wc->tspans[lc->sync - 1]->sync = span->spanno;
		wc->tspans[lc->sync - 1]->psync = span->offset + 1;
	}
	wc->checktiming = 1;
	/* If we're already running, then go ahead and apply the changes */
	if (span->flags & ZT_FLAG_RUNNING)
		return t4_startup(span);
	printk("Done with spanconfig!\n");
	return 0;
}

static int t4_chanconfig(struct zt_chan *chan, int sigtype)
{
	int alreadyrunning;
	unsigned long flags;
	struct t4 *wc = chan->pvt;

	alreadyrunning = wc->tspans[chan->span->offset]->span.flags & ZT_FLAG_RUNNING;
	if (debug & DEBUG_MAIN) {
		if (alreadyrunning)
			printk("TE%dXXP: Reconfigured channel %d (%s) sigtype %d\n", wc->numspans, chan->channo, chan->name, sigtype);
		else
			printk("TE%dXXP: Configured channel %d (%s) sigtype %d\n", wc->numspans, chan->channo, chan->name, sigtype);
	}		
	spin_lock_irqsave(&wc->reglock, flags);	
	if (alreadyrunning)
		__set_clear(wc, chan->span->offset);
	spin_unlock_irqrestore(&wc->reglock, flags);	
	return 0;
}

static int t4_open(struct zt_chan *chan)
{
#ifndef LINUX26
	MOD_INC_USE_COUNT;
#else
	try_module_get(THIS_MODULE);
#endif	

	return 0;
}

static int t4_close(struct zt_chan *chan)
{
#ifndef LINUX26
	MOD_DEC_USE_COUNT;
#else
	module_put(THIS_MODULE);
#endif
	return 0;
}

static void init_spans(struct t4 *wc)
{
	int x,y,c;
	int gen2;
	int offset = 1;
	struct t4_span *ts;
	
	gen2 = (wc->tspans[0]->spanflags & FLAG_2NDGEN);
	if (!wc->t1e1)
		offset += 4;
	for (x=0;x<wc->numspans;x++) {
		ts = wc->tspans[x];
		sprintf(ts->span.name, "TE%d/%d/%d", wc->numspans,
		       wc->num, x + 1);
		sprintf(ts->span.desc, "T%dXXP (PCI) Card %d Span %d", wc->numspans, wc->num, x+1);
		ts->span.spanconfig = t4_spanconfig;
		ts->span.chanconfig = t4_chanconfig;
		ts->span.startup = t4_startup;
		ts->span.shutdown = t4_shutdown;
		ts->span.rbsbits = t4_rbsbits;
		ts->span.maint = t4_maint;
		ts->span.open = t4_open;
		ts->span.close  = t4_close;
		if (ts->spantype == TYPE_T1 || ts->spantype == TYPE_J1) {
			ts->span.channels = 24;
			ts->span.deflaw = ZT_LAW_MULAW;
		} else {
			ts->span.channels = 31;
			ts->span.deflaw = ZT_LAW_ALAW;
		}
		ts->span.chans = ts->chans;
		ts->span.flags = ZT_FLAG_RBS;
		ts->span.linecompat = ZT_CONFIG_AMI | ZT_CONFIG_B8ZS | ZT_CONFIG_D4 | ZT_CONFIG_ESF;
		ts->span.ioctl = t4_ioctl;
		if (gen2) {
#ifdef VPM_SUPPORT
			ts->span.echocan = t4_echocan;
#endif			
			ts->span.dacs = t4_dacs;
		}
		ts->span.pvt = ts;
		ts->owner = wc;
		ts->span.offset = x;
		ts->writechunk = (void *)(wc->writechunk + x * 32 * 2);
		ts->readchunk = (void *)(wc->readchunk + x * 32 * 2);
		init_waitqueue_head(&ts->span.maintq);
		for (y=0;y<wc->tspans[x]->span.channels;y++) {
			struct zt_chan *mychans = ts->chans + y;
			sprintf(mychans->name, "TE%d/%d/%d/%d", wc->numspans, wc->num, x + 1, y + 1);
			mychans->sigcap = ZT_SIG_EM | ZT_SIG_CLEAR | ZT_SIG_FXSLS | ZT_SIG_FXSGS | ZT_SIG_FXSKS |
									 ZT_SIG_FXOLS | ZT_SIG_FXOGS | ZT_SIG_FXOKS | ZT_SIG_CAS | ZT_SIG_EM_E1 | ZT_SIG_DACS_RBS;
			c = (x * ts->span.channels) + y;
			mychans->pvt = wc;
			mychans->chanpos = y + 1;
			if (gen2) {
				mychans->writechunk = (void *)(wc->writechunk + (x * 32 + y + offset) * 2);
				mychans->readchunk = (void *)(wc->readchunk + (x * 32 + y + offset) * 2);
			}
		}
	}
}

static void t4_serial_setup(struct t4 *wc, int unit)
{
	if (!wc->globalconfig) {
		wc->globalconfig = 1;
		printk("TE%dXXP: Setting up global serial parameters\n", wc->numspans);
		t4_framer_out(wc, 0, 0x85, 0xe0);	/* GPC1: Multiplex mode enabled, FSC is output, active low, RCLK from channel 0 */
		t4_framer_out(wc, 0, 0x08, 0x01);	/* IPC: Interrupt push/pull active low */
	
		/* Global clocks (8.192 Mhz CLK) */
		t4_framer_out(wc, 0, 0x92, 0x00);	
		t4_framer_out(wc, 0, 0x93, 0x18);
		t4_framer_out(wc, 0, 0x94, 0xfb);
		t4_framer_out(wc, 0, 0x95, 0x0b);
		t4_framer_out(wc, 0, 0x96, 0x00);
		t4_framer_out(wc, 0, 0x97, 0x0b);
		t4_framer_out(wc, 0, 0x98, 0xdb);
		t4_framer_out(wc, 0, 0x99, 0xdf);
	}

	/* Configure interrupts */	
	t4_framer_out(wc, unit, 0x46, 0x00);	/* GCR: Interrupt on Activation/Deactivation of each */

	/* Configure system interface */
	t4_framer_out(wc, unit, 0x3e, 0xc2);	/* SIC1: 8.192 Mhz clock/bus, double buffer receive / transmit, byte interleaved */
	t4_framer_out(wc, unit, 0x3f, 0x20 | (unit << 1)); /* SIC2: No FFS, no center receive eliastic buffer, phase */
	t4_framer_out(wc, unit, 0x40, 0x04);	/* SIC3: Edges for capture */
	t4_framer_out(wc, unit, 0x45, 0x00);	/* CMR2: We provide sync and clock for tx and rx. */
	if (!wc->t1e1) { /* T1 mode */
		t4_framer_out(wc, unit, 0x22, 0x03);	/* XC0: Normal operation of Sa-bits */
		t4_framer_out(wc, unit, 0x23, 0x84);	/* XC1: 0 offset */
		if (wc->tspans[unit]->spantype == TYPE_J1)
			t4_framer_out(wc, unit, 0x24, 0x83);	/* RC0: Just shy of 1023 */
		else
			t4_framer_out(wc, unit, 0x24, 0x03);	/* RC0: Just shy of 1023 */
		t4_framer_out(wc, unit, 0x25, 0x84);	/* RC1: The rest of RC0 */
	} else { /* E1 mode */
		t4_framer_out(wc, unit, 0x22, 0x00);	/* XC0: Normal operation of Sa-bits */
		t4_framer_out(wc, unit, 0x23, 0x04);	/* XC1: 0 offset */
		t4_framer_out(wc, unit, 0x24, 0x04);	/* RC0: Just shy of 1023 */
		t4_framer_out(wc, unit, 0x25, 0x04);	/* RC1: The rest of RC0 */
	}
	
	/* Configure ports */
	t4_framer_out(wc, unit, 0x80, 0x00);	/* PC1: SPYR/SPYX input on RPA/XPA */
	t4_framer_out(wc, unit, 0x81, 0x22);	/* PC2: RMFB/XSIG output/input on RPB/XPB */
	t4_framer_out(wc, unit, 0x82, 0x65);	/* PC3: Some unused stuff */
	t4_framer_out(wc, unit, 0x83, 0x35);	/* PC4: Some more unused stuff */
	t4_framer_out(wc, unit, 0x84, 0x01);	/* PC5: XMFS active low, SCLKR is input, RCLK is output */
	if (debug & DEBUG_MAIN)
		printk("Successfully initialized serial bus for unit %d\n", unit);
}

static void __t4_set_timing_source(struct t4 *wc, int unit)
{
	unsigned int timing;
	int x;
	if (unit != wc->syncsrc) {
		timing = 0x34;		/* CMR1: RCLK unit, 8.192 Mhz TCLK, RCLK is 8.192 Mhz */
		if ((unit > -1) && (unit < 4)) {
			timing |= (unit << 6);
			for (x=0;x<wc->numspans;x++)  /* set all 4 receive reference clocks to unit */
				__t4_framer_out(wc, x, 0x44, timing);
			wc->dmactrl |= (1 << 29);
			__t4_pci_out(wc, WC_DMACTRL, wc->dmactrl);
		} else {
			for (x=0;x<wc->numspans;x++) /* set each receive reference clock to itself */
				__t4_framer_out(wc, x, 0x44, timing | (x << 6));
			wc->dmactrl &= ~(1 << 29);
			__t4_pci_out(wc, WC_DMACTRL, wc->dmactrl);
		}
		wc->syncsrc = unit;
		if ((unit < 0) || (unit > 3))
			unit = 0;
		else
			unit++;
		for (x=0;x<wc->numspans;x++)
			wc->tspans[x]->span.syncsrc = unit;
	} else {
		if (debug & DEBUG_MAIN)
			printk("TE%dXXP: Timing source already set to %d\n", wc->numspans, unit);
	}
#if	0
	printk("wct4xxp: Timing source set to %d\n",unit);
#endif
}

static void __t4_set_timing_source_auto(struct t4 *wc)
{
	int x;
	wc->checktiming = 0;
	for (x=0;x<wc->numspans;x++) {
		if (wc->tspans[x]->sync) {
			if ((wc->tspans[wc->tspans[x]->psync - 1]->span.flags & ZT_FLAG_RUNNING) && 
				!(wc->tspans[wc->tspans[x]->psync - 1]->span.alarms & (ZT_ALARM_RED | ZT_ALARM_BLUE) )) {
					/* Valid timing source */
					__t4_set_timing_source(wc, wc->tspans[x]->psync - 1);
					return;
			}
		}
	}
	__t4_set_timing_source(wc, 4);
}

static void __t4_configure_t1(struct t4 *wc, int unit, int lineconfig, int txlevel)
{
	unsigned int fmr4, fmr2, fmr1, fmr0, lim2;
	char *framing, *line;
	int mytxlevel;
	if ((txlevel > 7) || (txlevel < 4))
		mytxlevel = 0;
	else
		mytxlevel = txlevel - 4;
	fmr1 = 0x9c; /* FMR1: Mode 1, T1 mode, CRC on for ESF, 8.192 Mhz system data rate, no XAIS */
	fmr2 = 0x22; /* FMR2: no payload loopback, auto send yellow alarm */
	if (loopback)
		fmr2 |= 0x4;
	fmr4 = 0x0c; /* FMR4: Lose sync on 2 out of 5 framing bits, auto resync */
	lim2 = 0x21; /* LIM2: 50% peak is a "1", Advanced Loss recovery */
	lim2 |= (mytxlevel << 6);	/* LIM2: Add line buildout */
	__t4_framer_out(wc, unit, 0x1d, fmr1);
	__t4_framer_out(wc, unit, 0x1e, fmr2);

	/* Configure line interface */
	if (lineconfig & ZT_CONFIG_AMI) {
		line = "AMI";
		fmr0 = 0xa0;
	} else {
		line = "B8ZS";
		fmr0 = 0xf0;
	}
	if (lineconfig & ZT_CONFIG_D4) {
		framing = "D4";
	} else {
		framing = "ESF";
		fmr4 |= 0x2;
		fmr2 |= 0xc0;
	}
	__t4_framer_out(wc, unit, 0x1c, fmr0);
	__t4_framer_out(wc, unit, 0x20, fmr4);
	__t4_framer_out(wc, unit, 0x21, 0x40);	/* FMR5: Enable RBS mode */

	__t4_framer_out(wc, unit, 0x37, 0xf0 );	/* LIM1: Clear data in case of LOS, Set receiver threshold (0.5V), No remote loop, no DRS */
	__t4_framer_out(wc, unit, 0x36, 0x08);	/* LIM0: Enable auto long haul mode, no local loop (must be after LIM1) */

	__t4_framer_out(wc, unit, 0x02, 0x50);	/* CMDR: Reset the receiver and transmitter line interface */
	__t4_framer_out(wc, unit, 0x02, 0x00);	/* CMDR: Reset the receiver and transmitter line interface */

	__t4_framer_out(wc, unit, 0x3a, lim2);	/* LIM2: 50% peak amplitude is a "1" */
	__t4_framer_out(wc, unit, 0x38, 0x0a);	/* PCD: LOS after 176 consecutive "zeros" */
	__t4_framer_out(wc, unit, 0x39, 0x15);	/* PCR: 22 "ones" clear LOS */
	
	/* Generate pulse mask for T1 */
	switch(mytxlevel) {
	case 3:
		__t4_framer_out(wc, unit, 0x26, 0x07);	/* XPM0 */
		__t4_framer_out(wc, unit, 0x27, 0x01);	/* XPM1 */
		__t4_framer_out(wc, unit, 0x28, 0x00);	/* XPM2 */
		break;
	case 2:
		__t4_framer_out(wc, unit, 0x26, 0x8c);	/* XPM0 */
		__t4_framer_out(wc, unit, 0x27, 0x11);	/* XPM1 */
		__t4_framer_out(wc, unit, 0x28, 0x01);	/* XPM2 */
		break;
	case 1:
		__t4_framer_out(wc, unit, 0x26, 0x8c);	/* XPM0 */
		__t4_framer_out(wc, unit, 0x27, 0x01);	/* XPM1 */
		__t4_framer_out(wc, unit, 0x28, 0x00);	/* XPM2 */
		break;
	case 0:
	default:
		__t4_framer_out(wc, unit, 0x26, 0xd7);	/* XPM0 */
		__t4_framer_out(wc, unit, 0x27, 0x22);	/* XPM1 */
		__t4_framer_out(wc, unit, 0x28, 0x01);	/* XPM2 */
		break;
	}

	__t4_framer_out(wc, unit, 0x14, 0xff);	/* IMR0: We care about CAS changes, etc */
	__t4_framer_out(wc, unit, 0x15, 0xff);	/* IMR1: We care about nothing */
	__t4_framer_out(wc, unit, 0x16, 0x00);	/* IMR2: We care about all the alarm stuff! */
	if (debugslips) {
		__t4_framer_out(wc, unit, 0x17, 0xf4);	/* IMR3: We care about AIS and friends */
		__t4_framer_out(wc, unit, 0x18, 0x3f);  /* IMR4: We care about slips on transmit */
	} else {
		__t4_framer_out(wc, unit, 0x17, 0xf7);	/* IMR3: We care about AIS and friends */
		__t4_framer_out(wc, unit, 0x18, 0xff);  /* IMR4: We don't care about slips on transmit */
	}

	if (!polling) {
		__t4_check_alarms(wc, unit);
		__t4_check_sigbits(wc, unit);
	}		
		
	printk("TE%dXXP: Span %d configured for %s/%s\n", wc->numspans, unit + 1, framing, line);
}

static void __t4_configure_e1(struct t4 *wc, int unit, int lineconfig)
{
	unsigned int fmr2, fmr1, fmr0;
	unsigned int cas = 0;
	unsigned int imr3extra=0;
	char *crc4 = "";
	char *framing, *line;
	fmr1 = 0x44; /* FMR1: E1 mode, Automatic force resync, PCM30 mode, 8.192 Mhz backplane, no XAIS */
	fmr2 = 0x03; /* FMR2: Auto transmit remote alarm, auto loss of multiframe recovery, no payload loopback */
	if (loopback)
		fmr2 |= 0x4;
	if (lineconfig & ZT_CONFIG_CRC4) {
		fmr1 |= 0x08;	/* CRC4 transmit */
		fmr2 |= 0xc0;	/* CRC4 receive */
		crc4 = "/CRC4";
	}
	__t4_framer_out(wc, unit, 0x1d, fmr1);
	__t4_framer_out(wc, unit, 0x1e, fmr2);

	/* Configure line interface */
	if (lineconfig & ZT_CONFIG_AMI) {
		line = "AMI";
		fmr0 = 0xa0;
	} else {
		line = "HDB3";
		fmr0 = 0xf0;
	}
	if (lineconfig & ZT_CONFIG_CCS) {
		framing = "CCS";
		imr3extra = 0x28;
	} else {
		framing = "CAS";
		cas = 0x40;
	}
	__t4_framer_out(wc, unit, 0x1c, fmr0);

	__t4_framer_out(wc, unit, 0x37, 0xf0 /*| 0x6 */ );	/* LIM1: Clear data in case of LOS, Set receiver threshold (0.5V), No remote loop, no DRS */
	__t4_framer_out(wc, unit, 0x36, 0x08);	/* LIM0: Enable auto long haul mode, no local loop (must be after LIM1) */

	__t4_framer_out(wc, unit, 0x02, 0x50);	/* CMDR: Reset the receiver and transmitter line interface */
	__t4_framer_out(wc, unit, 0x02, 0x00);	/* CMDR: Reset the receiver and transmitter line interface */

	/* Condition receive line interface for E1 after reset */
	__t4_framer_out(wc, unit, 0xbb, 0x17);
	__t4_framer_out(wc, unit, 0xbc, 0x55);
	__t4_framer_out(wc, unit, 0xbb, 0x97);
	__t4_framer_out(wc, unit, 0xbb, 0x11);
	__t4_framer_out(wc, unit, 0xbc, 0xaa);
	__t4_framer_out(wc, unit, 0xbb, 0x91);
	__t4_framer_out(wc, unit, 0xbb, 0x12);
	__t4_framer_out(wc, unit, 0xbc, 0x55);
	__t4_framer_out(wc, unit, 0xbb, 0x92);
	__t4_framer_out(wc, unit, 0xbb, 0x0c);
	__t4_framer_out(wc, unit, 0xbb, 0x00);
	__t4_framer_out(wc, unit, 0xbb, 0x8c);
	
	__t4_framer_out(wc, unit, 0x3a, 0x20);	/* LIM2: 50% peak amplitude is a "1" */
	__t4_framer_out(wc, unit, 0x38, 0x0a);	/* PCD: LOS after 176 consecutive "zeros" */
	__t4_framer_out(wc, unit, 0x39, 0x15);	/* PCR: 22 "ones" clear LOS */
	
	__t4_framer_out(wc, unit, 0x20, 0x9f);	/* XSW: Spare bits all to 1 */
	__t4_framer_out(wc, unit, 0x21, 0x1c|cas);	/* XSP: E-bit set when async. AXS auto, XSIF to 1 */
	
	
	/* Generate pulse mask for E1 */
	__t4_framer_out(wc, unit, 0x26, 0x54);	/* XPM0 */
	__t4_framer_out(wc, unit, 0x27, 0x02);	/* XPM1 */
	__t4_framer_out(wc, unit, 0x28, 0x00);	/* XPM2 */

	__t4_framer_out(wc, unit, 0x14, 0xff);	/* IMR0: We care about CRC errors, CAS changes, etc */
	__t4_framer_out(wc, unit, 0x15, 0x3f);	/* IMR1: We care about loopup / loopdown */
	__t4_framer_out(wc, unit, 0x16, 0x00);	/* IMR2: We care about all the alarm stuff! */
	if (debugslips) {
		__t4_framer_out(wc, unit, 0x17, 0xc4 | imr3extra);	/* IMR3: We care about AIS and friends */
		__t4_framer_out(wc, unit, 0x18, 0x3f);  /* IMR4: We care about slips on transmit */
	} else {
		__t4_framer_out(wc, unit, 0x17, 0xc7 | imr3extra);	/* IMR3: We care about AIS and friends */
		__t4_framer_out(wc, unit, 0x18, 0xff);  /* IMR4: We don't care about slips on transmit */
	}
	if (!polling) {
		__t4_check_alarms(wc, unit);
		__t4_check_sigbits(wc, unit);
	}
	printk("TE%dXXP: Span %d configured for %s/%s%s\n", wc->numspans, unit + 1, framing, line, crc4);
}

static int t4_startup(struct zt_span *span)
{
#ifdef SUPPORT_GEN1
	int i;
#endif
	int tspan;
	unsigned long flags;
	int alreadyrunning;
	struct t4_span *ts = span->pvt;
	struct t4 *wc = ts->owner;

	printk("About to enter startup!\n");
	tspan = span->offset + 1;
	if (tspan < 0) {
		printk("TE%dXXP: Span '%d' isn't us?\n", wc->numspans, span->spanno);
		return -1;
	}

	spin_lock_irqsave(&wc->reglock, flags);

	alreadyrunning = span->flags & ZT_FLAG_RUNNING;

#ifdef SUPPORT_GEN1
	/* initialize the start value for the entire chunk of last ec buffer */
	for(i = 0; i < span->channels; i++)
	{
		memset(ts->ec_chunk1[i],
			ZT_LIN2X(0,&span->chans[i]),ZT_CHUNKSIZE);
		memset(ts->ec_chunk2[i],
			ZT_LIN2X(0,&span->chans[i]),ZT_CHUNKSIZE);
	}
#endif
	/* Force re-evaluation fo timing source */
	if (timingcable)
		wc->syncsrc = -1;

	if (ts->spantype == TYPE_E1) { /* if this is an E1 card */
		__t4_configure_e1(wc, span->offset, span->lineconfig);
	} else { /* is a T1 card */
		__t4_configure_t1(wc, span->offset, span->lineconfig, span->txlevel);
	}
	/* Note clear channel status */
	__set_clear(wc, span->offset);
	
	if (!alreadyrunning) {
		span->flags |= ZT_FLAG_RUNNING;
		wc->spansstarted++;
			/* enable interrupts */
		/* Start DMA, enabling DMA interrupts on read only */
		if (ts->spanflags & FLAG_2NDGEN)
#ifdef VPM_SUPPORT
			wc->dmactrl = 0xc0000000 | (1 << 29) | wc->vpm;
#else
			wc->dmactrl = 0xc0000000 | (1 << 29);
#endif			
		else
#ifdef VPM_SUPPORT
			wc->dmactrl = 0xc0000003 | (1 << 29) | wc->vpm;
#else
			wc->dmactrl = 0xc0000003 | (1 << 29);
#endif
		if (noburst)
			wc->dmactrl |= (1 << 26);
		__t4_pci_out(wc, WC_DMACTRL, wc->dmactrl);
		if (!polling) {
			__t4_check_alarms(wc, span->offset);
			__t4_check_sigbits(wc, span->offset);
		}
	}

	spin_unlock_irqrestore(&wc->reglock, flags);
	if (wc->tspans[0]->sync == span->spanno) printk("SPAN %d: Primary Sync Source\n",span->spanno);
	if (wc->tspans[1]->sync == span->spanno) printk("SPAN %d: Secondary Sync Source\n",span->spanno);
	if (wc->numspans == 4) {
		if (wc->tspans[2]->sync == span->spanno) printk("SPAN %d: Tertiary Sync Source\n",span->spanno);
		if (wc->tspans[3]->sync == span->spanno) printk("SPAN %d: Quaternary Sync Source\n",span->spanno);
	}
#ifdef VPM_SUPPORT
	if (!alreadyrunning && !wc->vpm) {
        wait_a_little();
        t4_vpm_init(wc);
	}
#endif
	printk("Completed startup!\n");
	return 0;
}

#ifdef SUPPORT_GEN1
static inline void e1_check(struct t4 *wc, int span, int val)
{
	struct t4_span *ts = wc->tspans[span];
	if ((ts->span.channels > 24) &&
	    (ts->span.flags & ZT_FLAG_RUNNING) &&
	    !(ts->span.alarms) &&
	    (!wc->e1recover))   {
		if (val != 0x1b) {
			ts->e1check++;
		} else
			ts->e1check = 0;
		if (ts->e1check > 100) {
			/* Wait 1000 ms */
			wc->e1recover = 1000 * 8;
			wc->tspans[0]->e1check = wc->tspans[1]->e1check = 0;
			if (wc->numspans == 4)
				wc->tspans[2]->e1check = wc->tspans[3]->e1check = 0;
			if (debug & DEBUG_MAIN)
				printk("Detected loss of E1 alignment on span %d!\n", span);
			t4_reset_dma(wc);
		}
	}
}

static void t4_receiveprep(struct t4 *wc, int irq)
{
	volatile unsigned int *readchunk;
	int dbl = 0;
	int x,y,z;
	unsigned int tmp;
	int offset=0;
	if (!wc->t1e1)
		offset = 4;
	if (irq & 1) {
		/* First part */
		readchunk = wc->readchunk;
		if (!wc->last0) 
			dbl = 1;
		wc->last0 = 0;
	} else {
		readchunk = wc->readchunk + ZT_CHUNKSIZE * 32;
		if (wc->last0) 
			dbl = 1;
		wc->last0 = 1;
	}
	if (dbl) {
		for (x=0;x<wc->numspans;x++)
			wc->tspans[x]->irqmisses++;
		if (debug & DEBUG_MAIN)
			printk("TE%dXXP: Double/missed interrupt detected\n", wc->numspans);
	}
	for (x=0;x<ZT_CHUNKSIZE;x++) {
		for (z=0;z<24;z++) {
			/* All T1/E1 channels */
			tmp = readchunk[z+1+offset];
			if (wc->numspans == 4) {
				wc->tspans[3]->span.chans[z].readchunk[x] = tmp & 0xff;
				wc->tspans[2]->span.chans[z].readchunk[x] = (tmp & 0xff00) >> 8;
			}
			wc->tspans[1]->span.chans[z].readchunk[x] = (tmp & 0xff0000) >> 16;
			wc->tspans[0]->span.chans[z].readchunk[x] = tmp >> 24;
		}
		if (wc->t1e1) {
			if (wc->e1recover > 0)
				wc->e1recover--;
			tmp = readchunk[0];
			if (wc->numspans == 4) {
				e1_check(wc, 3, (tmp & 0x7f));
				e1_check(wc, 2, (tmp & 0x7f00) >> 8);
			}
			e1_check(wc, 1, (tmp & 0x7f0000) >> 16);
			e1_check(wc, 0, (tmp & 0x7f000000) >> 24);
			for (z=24;z<31;z++) {
				/* Only E1 channels now */
				tmp = readchunk[z+1];
				if (wc->numspans == 4) {
					if (wc->tspans[3]->span.channels > 24)
						wc->tspans[3]->span.chans[z].readchunk[x] = tmp & 0xff;
					if (wc->tspans[2]->span.channels > 24)
						wc->tspans[2]->span.chans[z].readchunk[x] = (tmp & 0xff00) >> 8;
				}
				if (wc->tspans[1]->span.channels > 24)
					wc->tspans[1]->span.chans[z].readchunk[x] = (tmp & 0xff0000) >> 16;
				if (wc->tspans[0]->span.channels > 24)
					wc->tspans[0]->span.chans[z].readchunk[x] = tmp >> 24;
			}
		}
		/* Advance pointer by 4 TDM frame lengths */
		readchunk += 32;
	}
	for (x=0;x<wc->numspans;x++) {
		if (wc->tspans[x]->span.flags & ZT_FLAG_RUNNING) {
			for (y=0;y<wc->tspans[x]->span.channels;y++) {
				/* Echo cancel double buffered data */
				zt_ec_chunk(&wc->tspans[x]->span.chans[y], 
				    wc->tspans[x]->span.chans[y].readchunk, 
					wc->tspans[x]->ec_chunk2[y]);
				memcpy(wc->tspans[x]->ec_chunk2[y],wc->tspans[x]->ec_chunk1[y],
					ZT_CHUNKSIZE);
				memcpy(wc->tspans[x]->ec_chunk1[y],
					wc->tspans[x]->span.chans[y].writechunk,
						ZT_CHUNKSIZE);
			}
			zt_receive(&wc->tspans[x]->span);
		}
	}
}
#endif

#if (ZT_CHUNKSIZE != 8)
#error Sorry, nextgen does not support chunksize != 8
#endif

static inline void __receive_span(struct t4_span *ts)
{
#ifdef VPM_SUPPORT
	int y;
	unsigned int merged;
	if ((merged = ts->dtmfactive & ts->dtmfmutemask)) {
		for (y=0;y<ts->span.channels;y++) {
			/* Mute any DTMFs which are supposed to be muted */
			if (merged & (1 << y)) 
				memset(ts->span.chans[y].readchunk, ZT_XLAW(0, (ts->span.chans + y)), ZT_CHUNKSIZE);
		}
	}
#endif	

#ifdef ENABLE_PREFETCH
	prefetch((void *)(ts->readchunk));
	prefetch((void *)(ts->writechunk));
	prefetch((void *)(ts->readchunk + 8));
	prefetch((void *)(ts->writechunk + 8));
	prefetch((void *)(ts->readchunk + 16));
	prefetch((void *)(ts->writechunk + 16));
	prefetch((void *)(ts->readchunk + 24));
	prefetch((void *)(ts->writechunk + 24));
	prefetch((void *)(ts->readchunk + 32));
	prefetch((void *)(ts->writechunk + 32));
	prefetch((void *)(ts->readchunk + 40));
	prefetch((void *)(ts->writechunk + 40));
	prefetch((void *)(ts->readchunk + 48));
	prefetch((void *)(ts->writechunk + 48));
	prefetch((void *)(ts->readchunk + 56));
	prefetch((void *)(ts->writechunk + 56));
#endif

	zt_ec_span(&ts->span);
	zt_receive(&ts->span);
}

static inline void __transmit_span(struct t4_span *ts)
{
	zt_transmit(&ts->span);
}

#ifdef ENABLE_WORKQUEUES
static void workq_handlespan(void *data)
{
	struct t4_span *ts = data;
	struct t4 *wc = ts->owner;
	
	__receive_span(ts);
	__transmit_span(ts);
	atomic_dec(&wc->worklist);
	if (!atomic_read(&wc->worklist))
		t4_pci_out(wc, WC_INTR, 0);
}
#else
static void t4_prep_gen2(struct t4 *wc)
{
	int x;
	for (x=0;x<wc->numspans;x++) {
		if (wc->tspans[x]->span.flags & ZT_FLAG_RUNNING) {
			__receive_span(wc->tspans[x]);
			__transmit_span(wc->tspans[x]);
		}
	}
}

#endif
#ifdef SUPPORT_GEN1
static void t4_transmitprep(struct t4 *wc, int irq)
{
	volatile unsigned int *writechunk;
	int x,y,z;
	unsigned int tmp;
	int offset=0;
	if (!wc->t1e1)
		offset = 4;
	if (irq & 1) {
		/* First part */
		writechunk = wc->writechunk + 1;
	} else {
		writechunk = wc->writechunk + ZT_CHUNKSIZE * 32  + 1;
	}
	for (y=0;y<wc->numspans;y++) {
		if (wc->tspans[y]->span.flags & ZT_FLAG_RUNNING) 
			zt_transmit(&wc->tspans[y]->span);
	}

	for (x=0;x<ZT_CHUNKSIZE;x++) {
		/* Once per chunk */
		for (z=0;z<24;z++) {
			/* All T1/E1 channels */
			tmp = (wc->tspans[3]->span.chans[z].writechunk[x]) | 
				  (wc->tspans[2]->span.chans[z].writechunk[x] << 8) |
				  (wc->tspans[1]->span.chans[z].writechunk[x] << 16) |
				  (wc->tspans[0]->span.chans[z].writechunk[x] << 24);
			writechunk[z+offset] = tmp;
		}
		if (wc->t1e1) {
			for (z=24;z<31;z++) {
				/* Only E1 channels now */
				tmp = 0;
				if (wc->numspans == 4) {
					if (wc->tspans[3]->span.channels > 24)
						tmp |= wc->tspans[3]->span.chans[z].writechunk[x];
					if (wc->tspans[2]->span.channels > 24)
						tmp |= (wc->tspans[2]->span.chans[z].writechunk[x] << 8);
				}
				if (wc->tspans[1]->span.channels > 24)
					tmp |= (wc->tspans[1]->span.chans[z].writechunk[x] << 16);
				if (wc->tspans[0]->span.channels > 24)
					tmp |= (wc->tspans[0]->span.chans[z].writechunk[x] << 24);
				writechunk[z] = tmp;
			}
		}
		/* Advance pointer by 4 TDM frame lengths */
		writechunk += 32;
	}

}
#endif

static void __t4_check_sigbits(struct t4 *wc, int span)
{
	int a,i,rxs;
	struct t4_span *ts = wc->tspans[span];

	if (debug & DEBUG_RBS)
		printk("Checking sigbits on span %d\n", span + 1);

	if (!(ts->span.flags & ZT_FLAG_RUNNING))
		return;
	if (ts->spantype == TYPE_E1) {
		for (i = 0; i < 15; i++) {
			a = __t4_framer_in(wc, span, 0x71 + i);
			/* Get high channel in low bits */
			rxs = (a & 0xf);
			if (!(ts->span.chans[i+16].sig & ZT_SIG_CLEAR)) {
				if (ts->span.chans[i+16].rxsig != rxs)
					zt_rbsbits(&ts->span.chans[i+16], rxs);
			}
			rxs = (a >> 4) & 0xf;
			if (!(ts->span.chans[i].sig & ZT_SIG_CLEAR)) {
				if (ts->span.chans[i].rxsig != rxs)
					zt_rbsbits(&ts->span.chans[i], rxs);
			}
		}
	} else if (ts->span.lineconfig & ZT_CONFIG_D4) {
		for (i = 0; i < 24; i+=4) {
			a = __t4_framer_in(wc, span, 0x70 + (i>>2));
			/* Get high channel in low bits */
			rxs = (a & 0x3) << 2;
			if (!(ts->span.chans[i+3].sig & ZT_SIG_CLEAR)) {
				if (ts->span.chans[i+3].rxsig != rxs)
					zt_rbsbits(&ts->span.chans[i+3], rxs);
			}
			rxs = (a & 0xc);
			if (!(ts->span.chans[i+2].sig & ZT_SIG_CLEAR)) {
				if (ts->span.chans[i+2].rxsig != rxs)
					zt_rbsbits(&ts->span.chans[i+2], rxs);
			}
			rxs = (a >> 2) & 0xc;
			if (!(ts->span.chans[i+1].sig & ZT_SIG_CLEAR)) {
				if (ts->span.chans[i+1].rxsig != rxs)
					zt_rbsbits(&ts->span.chans[i+1], rxs);
			}
			rxs = (a >> 4) & 0xc;
			if (!(ts->span.chans[i].sig & ZT_SIG_CLEAR)) {
				if (ts->span.chans[i].rxsig != rxs)
					zt_rbsbits(&ts->span.chans[i], rxs);
			}
		}
	} else {
		for (i = 0; i < 24; i+=2) {
			a = __t4_framer_in(wc, span, 0x70 + (i>>1));
			/* Get high channel in low bits */
			rxs = (a & 0xf);
			if (!(ts->span.chans[i+1].sig & ZT_SIG_CLEAR)) {
				/* XXX Not really reset on every trans! XXX */
				if (ts->span.chans[i+1].rxsig != rxs) {
					zt_rbsbits(&ts->span.chans[i+1], rxs);
				}
			}
			rxs = (a >> 4) & 0xf;
			if (!(ts->span.chans[i].sig & ZT_SIG_CLEAR)) {
				/* XXX Not really reset on every trans! XXX */
				if (ts->span.chans[i].rxsig != rxs) {
					zt_rbsbits(&ts->span.chans[i], rxs);
				}
			}
		}
	}
}

static void __t4_check_alarms(struct t4 *wc, int span)
{
	unsigned char c,d;
	int alarms;
	int x,j;
	struct t4_span *ts = wc->tspans[span];

	if (!(ts->span.flags & ZT_FLAG_RUNNING))
		return;

	c = __t4_framer_in(wc, span, 0x4c);
	d = __t4_framer_in(wc, span, 0x4d);

	/* Assume no alarms */
	alarms = 0;

	/* And consider only carrier alarms */
	ts->span.alarms &= (ZT_ALARM_RED | ZT_ALARM_BLUE | ZT_ALARM_NOTOPEN);

	if (ts->spantype == TYPE_E1) {
		if (c & 0x04) {
			/* No multiframe found, force RAI high after 400ms only if
			   we haven't found a multiframe since last loss
			   of frame */
			if (!(ts->spanflags & FLAG_NMF)) {
				__t4_framer_out(wc, span, 0x20, 0x9f | 0x20);	/* LIM0: Force RAI High */
				ts->spanflags |= FLAG_NMF;
				printk("NMF workaround on!\n");
			}
			__t4_framer_out(wc, span, 0x1e, 0xc3);	/* Reset to CRC4 mode */
			__t4_framer_out(wc, span, 0x1c, 0xf2);	/* Force Resync */
			__t4_framer_out(wc, span, 0x1c, 0xf0);	/* Force Resync */
		} else if (!(c & 0x02)) {
			if ((ts->spanflags & FLAG_NMF)) {
				__t4_framer_out(wc, span, 0x20, 0x9f);	/* LIM0: Clear forced RAI */
				ts->spanflags &= ~FLAG_NMF;
				printk("NMF workaround off!\n");
			}
		}
	} else {
		/* Detect loopup code if we're not sending one */
		if ((!ts->span.mainttimer) && (d & 0x08)) {
			/* Loop-up code detected */
			if ((ts->loopupcnt++ > 80)  && (ts->span.maintstat != ZT_MAINT_REMOTELOOP)) {
				__t4_framer_out(wc, span, 0x36, 0x08);	/* LIM0: Disable any local loop */
				__t4_framer_out(wc, span, 0x37, 0xf6 );	/* LIM1: Enable remote loop */
				ts->span.maintstat = ZT_MAINT_REMOTELOOP;
			}
		} else
			ts->loopupcnt = 0;
		/* Same for loopdown code */
		if ((!ts->span.mainttimer) && (d & 0x10)) {
			/* Loop-down code detected */
			if ((ts->loopdowncnt++ > 80)  && (ts->span.maintstat == ZT_MAINT_REMOTELOOP)) {
				__t4_framer_out(wc, span, 0x36, 0x08);	/* LIM0: Disable any local loop */
				__t4_framer_out(wc, span, 0x37, 0xf0 );	/* LIM1: Disable remote loop */
				ts->span.maintstat = ZT_MAINT_NONE;
			}
		} else
			ts->loopdowncnt = 0;
	}

	if (ts->span.lineconfig & ZT_CONFIG_NOTOPEN) {
		for (x=0,j=0;x < ts->span.channels;x++)
			if ((ts->span.chans[x].flags & ZT_FLAG_OPEN) ||
			    (ts->span.chans[x].flags & ZT_FLAG_NETDEV))
				j++;
		if (!j)
			alarms |= ZT_ALARM_NOTOPEN;
	}

	if (c & 0xa0) {
		if (ts->alarmcount >= alarmdebounce) 
			alarms |= ZT_ALARM_RED;
		else
			ts->alarmcount++;
	} else
		ts->alarmcount = 0;
	if (c & 0x4)
		alarms |= ZT_ALARM_BLUE;

	if (((!ts->span.alarms) && alarms) || 
	    (ts->span.alarms && (!alarms))) 
		wc->checktiming = 1;

	/* Keep track of recovering */
	if ((!alarms) && ts->span.alarms) 
		ts->alarmtimer = ZT_ALARMSETTLE_TIME;
	if (ts->alarmtimer)
		alarms |= ZT_ALARM_RECOVER;

	/* If receiving alarms, go into Yellow alarm state */
	if (alarms && !(ts->spanflags & FLAG_SENDINGYELLOW)) {
		unsigned char fmr4;
#if 1
		printk("wct%dxxp: Setting yellow alarm on span %d\n", wc->numspans, span + 1);
#endif
		/* We manually do yellow alarm to handle RECOVER and NOTOPEN, otherwise it's auto anyway */
		fmr4 = __t4_framer_in(wc, span, 0x20);
		__t4_framer_out(wc, span, 0x20, fmr4 | 0x20);
		ts->spanflags |= FLAG_SENDINGYELLOW;
	} else if ((!alarms) && (ts->spanflags & FLAG_SENDINGYELLOW)) {
		unsigned char fmr4;
#if 1
		printk("wct%dxxp: Clearing yellow alarm on span %d\n", wc->numspans, span + 1);
#endif
		/* We manually do yellow alarm to handle RECOVER  */
		fmr4 = __t4_framer_in(wc, span, 0x20);
		__t4_framer_out(wc, span, 0x20, fmr4 & ~0x20);
		ts->spanflags &= ~FLAG_SENDINGYELLOW;
	}

	/* Re-check the timing source when we enter/leave alarm, not withstanding
	   yellow alarm */
	if (c & 0x10)
		alarms |= ZT_ALARM_YELLOW;
	if (ts->span.mainttimer || ts->span.maintstat) 
		alarms |= ZT_ALARM_LOOPBACK;
	ts->span.alarms = alarms;
	zt_alarm_notify(&ts->span);
}

static void __t4_do_counters(struct t4 *wc)
{
	int span;
	for (span=0;span<wc->numspans;span++) {
		struct t4_span *ts = wc->tspans[span];
		if (ts->alarmtimer) {
			if (!--ts->alarmtimer) {
				ts->span.alarms &= ~(ZT_ALARM_RECOVER);
				if (!polling)
					__t4_check_alarms(wc, span);
				zt_alarm_notify(&ts->span);
			}
		}
	}
}

static inline void __handle_leds(struct t4 *wc)
{
	int x;

	wc->blinktimer++;
	for (x=0;x<wc->numspans;x++) {
		struct t4_span *ts = wc->tspans[x];
		if (ts->span.flags & ZT_FLAG_RUNNING) {
			if (ts->span.alarms & (ZT_ALARM_RED | ZT_ALARM_BLUE)) {
#ifdef FANCY_ALARM
				if (wc->blinktimer == (altab[wc->alarmpos] >> 1)) {
					__t4_set_led(wc, x, WC_RED);
				}
				if (wc->blinktimer == 0xf) {
					__t4_set_led(wc, x, WC_OFF);
				}
#else
				if (wc->blinktimer == 160) {
					__t4_set_led(wc, x, WC_RED);
				} else if (wc->blinktimer == 480) {
					__t4_set_led(wc, x, WC_OFF);
				}
#endif
			} else if (ts->span.alarms & ZT_ALARM_YELLOW) {
				/* Yellow Alarm */
				__t4_set_led(wc, x, WC_YELLOW);
			} else if (ts->span.mainttimer || ts->span.maintstat) {
#ifdef FANCY_ALARM
				if (wc->blinktimer == (altab[wc->alarmpos] >> 1)) {
					__t4_set_led(wc, x, WC_GREEN);
				}
				if (wc->blinktimer == 0xf) {
					__t4_set_led(wc, x, WC_OFF);
				}
#else
				if (wc->blinktimer == 160) {
					__t4_set_led(wc, x, WC_GREEN);
				} else if (wc->blinktimer == 480) {
					__t4_set_led(wc, x, WC_OFF);
				}
#endif
			} else {
				/* No Alarm */
				__t4_set_led(wc, x, WC_GREEN);
			}
		}	else
				__t4_set_led(wc, x, WC_OFF);

	}
#ifdef FANCY_ALARM
	if (wc->blinktimer == 0xf) {
		wc->blinktimer = -1;
		wc->alarmpos++;
		if (wc->alarmpos >= (sizeof(altab) / sizeof(altab[0])))
			wc->alarmpos = 0;
	}
#else
	if (wc->blinktimer == 480)
		wc->blinktimer = 0;
#endif
}

#ifdef SUPPORT_GEN1
#ifdef LINUX26
static irqreturn_t t4_interrupt(int irq, void *dev_id, struct pt_regs *regs)
#else
static void t4_interrupt(int irq, void *dev_id, struct pt_regs *regs)
#endif
{
	struct t4 *wc = dev_id;
	unsigned long flags;
	int x;
	
	unsigned int status;
#if 0
	unsigned int status2;
#endif

#if 0
	if (wc->intcount < 20)
		printk("Pre-interrupt\n");
#endif
	
	inirq = 1;
	/* Make sure it's really for us */
	status = t4_pci_in(wc, WC_INTR);
	t4_pci_out(wc, WC_INTR, 0);

	/* Ignore if it's not for us */
	if (!status)
#ifdef LINUX26
		return IRQ_NONE;
#else
		return;
#endif		

	if (!wc->spansstarted) {
		printk("Not prepped yet!\n");
#ifdef LINUX26
		return IRQ_NONE;
#else
		return;
#endif		
	}

	wc->intcount++;
#if 0
	if (wc->intcount < 20)
		printk("Got interrupt, status = %08x\n", status);
#endif		

	if (status & 0x3) {
		t4_receiveprep(wc, status);
		t4_transmitprep(wc, status);
	}
	
#if 0
	if ((wc->intcount < 10) || !(wc->intcount % 1000)) {
		status2 = t4_framer_in(wc, 0, 0x6f);
		printk("Status2: %04x\n", status2);
		for (x = 0;x<4;x++) {
			status2 = t4_framer_in(wc, x, 0x4c);
			printk("FRS0/%d: %04x\n", x, status2);
		}
	}
#endif
	spin_lock_irqsave(&wc->reglock, flags);

	__handle_leds(wc);

	__t4_do_counters(wc);

	x = wc->intcount & 15 /* 63 */;
	switch(x) {
	case 0:
	case 1:
	case 2:
	case 3:
		__t4_check_sigbits(wc, x);
		break;
	case 4:
	case 5:
	case 6:
	case 7:
		__t4_check_alarms(wc, x - 4);
		break;
	}

	if (wc->checktiming > 0)
		__t4_set_timing_source_auto(wc);
	spin_unlock_irqrestore(&wc->reglock, flags);
#ifdef LINUX26
	return IRQ_RETVAL(1);
#endif		
}
#endif

static inline void __t4_framer_interrupt(struct t4 *wc, int span)
{
	/* Check interrupts for a given span */
	unsigned char gis, isr0=0, isr1=0, isr2=0, isr3=0, isr4;
	struct t4_span *ts;

	if (debug & DEBUG_FRAMER)	
		printk("framer interrupt span %d:%d!\n", wc->num, span + 1);
	ts = wc->tspans[span];

	gis = __t4_framer_in(wc, span, 0x6e);
	
	if (ts->spantype == TYPE_E1) {
		/* E1 checks */
		if (gis & 0x1)
			isr0 = __t4_framer_in(wc, span, 0x68);
		if (gis & 0x2)
			isr1 = __t4_framer_in(wc, span, 0x69);
		if (gis & 0x4)
			isr2 = __t4_framer_in(wc, span, 0x6a);
		if (gis & 0x8)
			isr3 = __t4_framer_in(wc, span, 0x6b);


		if (isr0)  
			__t4_check_sigbits(wc, span);
		
		if ((isr3 & 0x38) || isr2 || isr1)
			__t4_check_alarms(wc, span);
		if (debug & DEBUG_FRAMER)
			printk("gis: %02x, isr0: %02x, isr1: %02x, isr2: %02x, isr3: %02x\n", gis, isr0, isr1, isr2, isr3);
	} else {
		/* T1 checks */
		if (gis & 0x1)
			isr0 = __t4_framer_in(wc, span, 0x68);
		if (gis & 0x4)
			isr2 = __t4_framer_in(wc, span, 0x6a);
		if (gis & 0x8)
			isr3 = __t4_framer_in(wc, span, 0x6b);

		if (isr0)
			__t4_check_sigbits(wc, span);
		if (isr2 || (isr3 & 0x08)) 
			__t4_check_alarms(wc, span);		
		if (debug & DEBUG_FRAMER)
			printk("gis: %02x, isr0: %02x, isr1: %02x, irs2: %02x, isr3: %02x\n", gis, isr0, isr1, isr2, isr3);	
	}
	if (debugslips && !ts->span.alarms) {
		if (isr3 & 0x02)
			printk("TE%d10P: RECEIVE slip NEGATIVE on span %d\n", wc->numspans, span + 1);
		if (isr3 & 0x01)
			printk("TE%d10P: RECEIVE slip POSITIVE on span %d\n", wc->numspans, span + 1);
		if (gis & 0x10)
			isr4 = __t4_framer_in(wc, span, 0x6c);
		else
			isr4 = 0;
		if (isr4 & 0x80)
			printk("TE%dXXP: TRANSMIT slip POSITIVE on span %d\n", wc->numspans, span + 1);
		if (isr4 & 0x40)
			printk("TE%d10P: TRANSMIT slip NEGATIVE on span %d\n", wc->numspans, span + 1);
	}
}

#ifdef LINUX26
static irqreturn_t t4_interrupt_gen2(int irq, void *dev_id, struct pt_regs *regs)
#else
static void t4_interrupt_gen2(int irq, void *dev_id, struct pt_regs *regs)
#endif
{
	struct t4 *wc = dev_id;
	unsigned long flags;
	unsigned char cis;
	int x;
	
	unsigned int status;
#if 0
	unsigned int status2;
#endif

#if 0
	if (wc->intcount < 20)
		printk("2G: Pre-interrupt\n");
#endif
	
	inirq = 1;
	/* Make sure it's really for us */
	status = t4_pci_in(wc, WC_INTR);
#if 1
	t4_pci_out(wc, WC_INTR, status & 0x00000008);
#endif

	/* Ignore if it's not for us */
	if (!(status & 0x7))
#ifdef LINUX26
		return IRQ_NONE;
#else
		return;
#endif		

	if (!wc->spansstarted) {
		printk("Not prepped yet!\n");
#ifdef LINUX26
		return IRQ_NONE;
#else
		return;
#endif		
	}

	wc->intcount++;
#if 1
	if (wc->intcount < 20)
		printk("2G: Got interrupt, status = %08x, GIS = %04x\n", status, __t4_framer_in(wc, 0, 0x6f));
#endif		

	if (status & 0x2) {
#ifdef ENABLE_WORKQUEUES
		int cpus = num_online_cpus();
		atomic_set(&wc->worklist, wc->numspans);
		if (wc->tspans[0]->span.flags & ZT_FLAG_RUNNING)
			t4_queue_work(wc->workq, &wc->tspans[0]->swork, 0);
		else
			atomic_dec(&wc->worklist);
		if (wc->tspans[1]->span.flags & ZT_FLAG_RUNNING)
			t4_queue_work(wc->workq, &wc->tspans[1]->swork, 1 % cpus);
		else
			atomic_dec(&wc->worklist);
		if (wc->numspans == 4) {
			if (wc->tspans[2]->span.flags & ZT_FLAG_RUNNING)
				t4_queue_work(wc->workq, &wc->tspans[2]->swork, 2 % cpus);
			else
				atomic_dec(&wc->worklist);
			if (wc->tspans[3]->span.flags & ZT_FLAG_RUNNING)
				t4_queue_work(wc->workq, &wc->tspans[3]->swork, 3 % cpus);
			else
				atomic_dec(&wc->worklist);
		}
#else
		t4_prep_gen2(wc);
#endif
	}

	spin_lock_irqsave(&wc->reglock, flags);

	if (status & 0x2)
		__t4_do_counters(wc);

	if (polling && (status & 0x2)) {
		x = wc->intcount & 15 /* 63 */;
		switch(x) {
		case 0:
		case 1:
		case 2:
		case 3:
			__t4_check_sigbits(wc, x);
			break;
		case 4:
		case 5:
		case 6:
		case 7:
			__t4_check_alarms(wc, x - 4);
			break;
		}
	} else if (status & 0x1) {
		cis = __t4_framer_in(wc, 0, 0x6f);
		if (cis & 0x1)
			__t4_framer_interrupt(wc, 0);
		if (cis & 0x2)
			__t4_framer_interrupt(wc, 1);
		if (cis & 0x4)
			__t4_framer_interrupt(wc, 2);
		if (cis & 0x8)
			__t4_framer_interrupt(wc, 3);
	}
#ifdef VPM_SUPPORT
	if (wc->vpm) {
		if (!(wc->intcount % 16)) {
			/* Check DTMF events */
			if (wc->vpm) {
				int span = (wc->intcount >> 4) & 0x3;
				int y;
				short energy;
				int offset = 1;
				int chip;
				int channel;
				struct t4_span *ts = wc->tspans[span];
				if (!wc->t1e1)
					offset = 5;
				if (ts->dtmfactive) {
					for (y = 0; y < ts->span.channels; y++) {
						if (ts->dtmfactive & (1 << y)) {
							channel = y + offset;
							chip = span + ((channel & 0x1) << 2);
							/* Have an active channel, check its energy! */
							energy = __t4_vpm_in(wc, chip, 0x58 + channel);
							energy = ZT_XLAW(energy, ts->span.chans);
							if (energy < (ts->dtmfenergy[y])) {
								if (debug & DEBUG_DTMF)
									printk("Finished digit on span %d, channel %d (energy = %02x < %02x) 'channel' %d, chip %d!\n", span, y + 1, energy, ts->dtmfenergy[y], channel, chip);
								if (debug & DEBUG_DTMF)	
									printk("Finished digit '%c' on channel %d of span %d\n", ts->dtmfdigit[y], y + 1, span);
								if (ts->dtmfmask & (1 << y))
									zt_qevent_lock(&ts->span.chans[y], (ZT_EVENT_DTMFUP | ts->dtmfdigit[y]));
								ts->dtmfenergy[y] = 0;
								ts->dtmfdigit[y] = 0;
								ts->dtmfactive &= ~(1 << y);
							} else if (energy > (ts->dtmfenergy[y])) {
								if (debug & DEBUG_DTMF)
									printk("Increasing digit energy on span %d, channel %d (energy = %02x > %02x)!\n", span, y + 1, energy, ts->dtmfenergy[y]);
								ts->dtmfenergy[y] = energy;
							}
						}
					}
				}
			}
		} else if ((status & 0xff00) != 0xff00)
			__t4_check_vpm(wc, (status & 0xff00) >> 8);
	}
#endif

#if 1 
	__handle_leds(wc);
#endif

	if (wc->checktiming > 0)
		__t4_set_timing_source_auto(wc);
	spin_unlock_irqrestore(&wc->reglock, flags);

#ifndef ENABLE_WORKQUEUES
	t4_pci_out(wc, WC_INTR, 0);
#endif	
#ifdef LINUX26
	return IRQ_RETVAL(1);
#endif		
}

#ifdef SUPPORT_GEN1
static int t4_reset_dma(struct t4 *wc)
{
	/* Turn off DMA and such */
	wc->dmactrl = 0x0;
	t4_pci_out(wc, WC_DMACTRL, wc->dmactrl);
	t4_pci_out(wc, WC_COUNT, 0);
	t4_pci_out(wc, WC_RDADDR, 0);
	t4_pci_out(wc, WC_WRADDR, 0);
	t4_pci_out(wc, WC_INTR, 0);
	/* Turn it all back on */
	t4_pci_out(wc, WC_RDADDR, wc->readdma);
	t4_pci_out(wc, WC_WRADDR, wc->writedma);
	t4_pci_out(wc, WC_COUNT, ((ZT_MAX_CHUNKSIZE * 2 * 32 - 1) << 18) | ((ZT_MAX_CHUNKSIZE * 2 * 32 - 1) << 2));
	t4_pci_out(wc, WC_INTR, 0);
#ifdef VPM_SUPPORT
	wc->dmactrl = 0xc0000000 | (1 << 29) | wc->vpm;
#else	
	wc->dmactrl = 0xc0000000 | (1 << 29);
#endif
	if (noburst)
		wc->dmactrl |= (1 << 26);
	t4_pci_out(wc, WC_DMACTRL, wc->dmactrl);
	return 0;
}
#endif

#ifdef VPM_SUPPORT
static void t4_vpm_init(struct t4 *wc)
{
	unsigned char reg;
	unsigned int mask;
	unsigned int ver;
	int i,x,y;
	if (!vpmsupport) {
		printk("VPM: Support Disabled\n");
		return;
	}

	for (x=0;x<8;x++) {
		struct t4_span *ts = wc->tspans[x & 0x3];
		ver = t4_vpm_in(wc, x, 0x1a0); /* revision */
		if (ver != 0x26) {
			if (x)
				printk("VPM: Inopperable\n");
			else
				printk("VPM: Not Present\n");
			return;
		}	

		/* Setup GPIO's */
		for (y=0;y<4;y++) {
			t4_vpm_out(wc, x, 0x1a8 + y, 0x00); /* GPIO out */
			t4_vpm_out(wc, x, 0x1ac + y, 0x00); /* GPIO dir */
			t4_vpm_out(wc, x, 0x1b0 + y, 0x00); /* GPIO sel */
		}

		/* Setup TDM path - sets fsync and tdm_clk as inputs */
		reg = t4_vpm_in(wc, x, 0x1a3); /* misc_con */
		t4_vpm_out(wc, x, 0x1a3, reg & ~2);

		/* Setup timeslots */
		t4_vpm_out(wc, x, 0x02f, 0x20 | ((x%4) << 3)); 
		if (x < 4)
			mask = 0x55555555;
		else
			mask = 0xaaaaaaaa;

		/* Setup Echo length (128 taps) */
		t4_vpm_out(wc, x, 0x022, 0x00);
		t4_vpm_out(wc, x, 0x023, 0x7f);
		
		/* Setup the tdm channel masks for all LV's*/
		for (i=0;i<4;i++)
			t4_vpm_out(wc, x, 0x30+i, (mask >> (i << 3)) & 0xff);

		/* Setup convergence rate */
		reg = t4_vpm_in(wc,x,0x20);
		reg &= 0xE0;
		if (ts->spantype == TYPE_E1) {
			if (x < 4)
				printk("VPM: Span %d A-law mode\n", x & 0x3);
			reg |= 0x01;
		} else {
			if (x < 4)
				printk("VPM: Span %d U-law mode\n", x & 0x3);
			reg &= ~0x01;
		}
		t4_vpm_out(wc,x,0x20,(reg | 0x20));
		
		/* Initialize echo cans */
		for (i = 0 ; i < MAX_TDM_CHAN ; i++) {
			if (mask & (0x00000001 << i))
				t4_vpm_out(wc,x,i,0x00);
		}

		wait_a_little();

		/* Put in bypass mode */
		for (i = 0 ; i < MAX_TDM_CHAN ; i++) {
			if (mask & (0x00000001 << i)) {
				t4_vpm_out(wc,x,i,0x01);
			}
		}

		/* Enable bypass */
		for (i = 0 ; i < MAX_TDM_CHAN ; i++) {
			if (mask & (0x00000001 << i))
				t4_vpm_out(wc,x,0x78 + i,0x01);
		}
      
        /* Enable DTMF detectors */
		for (i=0;i<MAX_DTMF_DET;i++) {
			if(x < 4)
				t4_vpm_out(wc, x, 0x98+i,(i*2)|0x40);
			else
				t4_vpm_out(wc, x, 0x98+i, ((i*2)+1)|0x40);
        }
		for (i=0xb8;i<0xbe;i++)
			t4_vpm_out(wc, x, i, 0xff);
		if(x < 4) {
			for(i=0;i<4;i++)
				t4_vpm_out(wc, x, 0xc0+i, 0x55);
		} else {
			for(i = 0; i < 4; i++)
				t4_vpm_out(wc, x, 0xc0+i, 0xaa);
		}
   } 
   printk("VPM: Present and operational\n");
   wc->vpm = T4_VPM_PRESENT;
}

#endif

static void t4_tsi_reset(struct t4 *wc) 
{
	int x;
	for (x=0;x<128;x++) {
		wc->dmactrl &= ~0x00007fff;
		wc->dmactrl |= (0x00004000 | (x << 7));
		t4_pci_out(wc, WC_DMACTRL, wc->dmactrl);
	}
	wc->dmactrl &= ~0x00007fff;
	t4_pci_out(wc, WC_DMACTRL, wc->dmactrl);
}

/* Note that channels here start from 1 */
static void t4_tsi_assign(struct t4 *wc, int fromspan, int fromchan, int tospan, int tochan)
{
	unsigned long flags;
	int fromts, tots;

	fromts = (fromspan << 5) |(fromchan);
	tots = (tospan << 5) | (tochan);

	if (!wc->t1e1) {
		fromts += 4;
		tots += 4;
	}
	spin_lock_irqsave(&wc->reglock, flags);
	wc->dmactrl &= ~0x00007fff;
	wc->dmactrl |= (0x00004000 | (tots << 7) | (fromts));
	__t4_pci_out(wc, WC_DMACTRL, wc->dmactrl);
	wc->dmactrl &= ~0x00007fff;
	__t4_pci_out(wc, WC_DMACTRL, wc->dmactrl);
	spin_unlock_irqrestore(&wc->reglock, flags);
}

static void t4_tsi_unassign(struct t4 *wc, int tospan, int tochan)
{
	unsigned long flags;
	int tots;

	tots = (tospan << 5) | (tochan);

	if (!wc->t1e1) 
		tots += 4;
	spin_lock_irqsave(&wc->reglock, flags);
	wc->dmactrl &= ~0x00007fff;
	wc->dmactrl |= (0x00004000 | (tots << 7));
	__t4_pci_out(wc, WC_DMACTRL, wc->dmactrl);
	if (debug & DEBUG_TSI)
		printk("Sending '%08x\n", wc->dmactrl);
	wc->dmactrl &= ~0x00007fff;
	__t4_pci_out(wc, WC_DMACTRL, wc->dmactrl);
	spin_unlock_irqrestore(&wc->reglock, flags);
}
static int t4_hardware_init_1(struct t4 *wc, int gen2)
{
	unsigned int version;

	version = t4_pci_in(wc, WC_VERSION);
	printk("TE%dXXP version %08x, burst %s, slip debug: %s\n", wc->numspans, version, noburst ? "OFF" : "ON", debugslips ? "ON" : "OFF");
#ifdef ENABLE_WORKQUEUES
	printk("TE%dXXP running with work queues.\n", wc->numspans);
#endif

	/* Make sure DMA engine is not running and interrupts are acknowledged */
	wc->dmactrl = 0x0;
	t4_pci_out(wc, WC_DMACTRL, wc->dmactrl);
	/* Reset Framer and friends */
	t4_pci_out(wc, WC_LEDS, 0x00000000);

	/* Set DMA addresses */
	t4_pci_out(wc, WC_RDADDR, wc->readdma);
	t4_pci_out(wc, WC_WRADDR, wc->writedma);

	/* Setup counters, interrupt flags (ignored in Gen2) */
	if (gen2) {
		t4_tsi_reset(wc);
	} else {
		t4_pci_out(wc, WC_COUNT, ((ZT_MAX_CHUNKSIZE * 2 * 32 - 1) << 18) | ((ZT_MAX_CHUNKSIZE * 2 * 32 - 1) << 2));
	}
	
	/* Reset pending interrupts */
	t4_pci_out(wc, WC_INTR, 0x00000000);

	/* Read T1/E1 status */
	if (t1e1override > -1)
		wc->t1e1 = t1e1override;
	else
		wc->t1e1 = ((t4_pci_in(wc, WC_LEDS)) & 0x0f00) >> 8;
	wc->order = ((t4_pci_in(wc, WC_LEDS)) & 0xf0000000) >> 28;
	return 0;
}

static int t4_hardware_init_2(struct t4 *wc)
{
	int x;
	unsigned int falcver;

	/* Setup LEDS, take out of reset */
	t4_pci_out(wc, WC_LEDS, 0x000000ff);
	t4_activate(wc);
	
	t4_framer_out(wc, 0, 0x4a, 0xaa);
	falcver = t4_framer_in(wc, 0 ,0x4a);
	printk("FALC version: %08x, Board ID: %02x\n", falcver, wc->order);

	for (x=0;x< 11;x++)
		printk("Reg %d: 0x%08x\n", x, t4_pci_in(wc, x));
	return 0;
}

static int __devinit t4_launch(struct t4 *wc)
{
	int x;
	unsigned long flags;
	if (wc->tspans[0]->span.flags & ZT_FLAG_REGISTERED)
		return 0;
	printk("TE%dXXP: Launching card: %d\n", wc->numspans, wc->order);

	/* Setup serial parameters and system interface */
	for (x=0;x<wc->numspans;x++)
		t4_serial_setup(wc, x);

	if (zt_register(&wc->tspans[0]->span, 0)) {
		printk(KERN_ERR "Unable to register span %s\n", wc->tspans[0]->span.name);
		return -1;
	}
	if (zt_register(&wc->tspans[1]->span, 0)) {
		printk(KERN_ERR "Unable to register span %s\n", wc->tspans[1]->span.name);
		zt_unregister(&wc->tspans[0]->span);
		return -1;
	}

	if (wc->numspans == 4) {
		if (zt_register(&wc->tspans[2]->span, 0)) {
			printk(KERN_ERR "Unable to register span %s\n", wc->tspans[2]->span.name);
			zt_unregister(&wc->tspans[0]->span);
			zt_unregister(&wc->tspans[1]->span);
			return -1;
		}
		if (zt_register(&wc->tspans[3]->span, 0)) {
			printk(KERN_ERR "Unable to register span %s\n", wc->tspans[3]->span.name);
			zt_unregister(&wc->tspans[0]->span);
			zt_unregister(&wc->tspans[1]->span);
			zt_unregister(&wc->tspans[2]->span);
			return -1;
		}
	}
	wc->checktiming = 1;
	spin_lock_irqsave(&wc->reglock, flags);
	__t4_set_timing_source(wc,4);
	spin_unlock_irqrestore(&wc->reglock, flags);
#ifdef ENABLE_TASKLETS
	tasklet_init(&wc->t4_tlet, t4_tasklet, (unsigned long)wc);
#endif
	return 0;
}

static int __devinit t4_init_one(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int res;
	struct t4 *wc;
	struct devtype *dt;
	int x,f;
	int basesize;
#if 0
	int y;
	unsigned int *canary;
#endif
	
	
	if (pci_enable_device(pdev)) {
		res = -EIO;
	} else {
		wc = kmalloc(sizeof(struct t4), GFP_KERNEL);
		if (wc) {
			memset(wc, 0x0, sizeof(struct t4));
			spin_lock_init(&wc->reglock);
			dt = (struct devtype *)(ent->driver_data);
			if (dt->flags & FLAG_2NDGEN)
				basesize = ZT_MAX_CHUNKSIZE * 32 * 4;
			else
				basesize = ZT_MAX_CHUNKSIZE * 32 * 2 * 4;

			if (dt->flags & FLAG_2PORT) 
				wc->numspans = 2;
			else
				wc->numspans = 4;

			wc->variety = dt->desc;

			wc->memaddr = pci_resource_start(pdev, 0);
			wc->memlen = pci_resource_len(pdev, 0);
			wc->membase = ioremap(wc->memaddr, wc->memlen);
			/* This rids of the Double missed interrupt message after loading */
			wc->last0 = 1;
#if 0
			if (!request_mem_region(wc->memaddr, wc->memlen, wc->variety))
				printk("wct4: Unable to request memory region :(, using anyway...\n");
#endif
			if (pci_request_regions(pdev, wc->variety))
				printk("wct%dxxp: Unable to request regions\n", wc->numspans);

			printk("Found TE%dXXP at base address %08lx, remapped to %p\n", wc->numspans, wc->memaddr, wc->membase);

			wc->dev = pdev;

			wc->writechunk = 
				/* 32 channels, Double-buffer, Read/Write, 4 spans */
				(unsigned int *)pci_alloc_consistent(pdev, basesize * 2, &wc->writedma);
			if (!wc->writechunk) {
				printk("wct%dxxp: Unable to allocate DMA-able memory\n", wc->numspans);
				return -ENOMEM;
			}

			/* Read is after the whole write piece (in words) */
			wc->readchunk = wc->writechunk + basesize / 4;

			/* Same thing but in bytes...  */
			wc->readdma = wc->writedma + basesize;

			/* Initialize Write/Buffers to all blank data */
			memset((void *)wc->writechunk,0x00, basesize);
			memset((void *)wc->readchunk,0xff, basesize);
#if 0
			memset((void *)wc->readchunk,0xff,ZT_MAX_CHUNKSIZE * 2 * 32 * 4);
			/* Initialize canary */
			canary = (unsigned int *)(wc->readchunk + ZT_CHUNKSIZE * 64 * 4 - 4);
			*canary = (CANARY << 16) | (0xffff);
#endif			

			/* Enable bus mastering */
			pci_set_master(pdev);

			/* Keep track of which device we are */
			pci_set_drvdata(pdev, wc);

			/* Initialize hardware */
			t4_hardware_init_1(wc, dt->flags & FLAG_2NDGEN);

			for(x = 0; x < MAX_T4_CARDS; x++) {
				if (!cards[x]) break;
			}

			if (x >= MAX_T4_CARDS) {
				printk("No cards[] slot available!!\n");
				return -ENOMEM;
			}

			wc->num = x;
			cards[x] = wc;
			

#ifdef ENABLE_WORKQUEUES
			if (dt->flags & FLAG_2NDGEN) {
				char tmp[20];
				sprintf(tmp, "te%dxxp[%d]", wc->numspans, wc->num);
				wc->workq = create_workqueue(tmp);
			}
#endif			

			/* Allocate pieces we need here */
			for (x=0;x<wc->numspans;x++) {
				if (wc->t1e1 & (1 << x)) {
					wc->tspans[x] = kmalloc(sizeof(struct t4_span) + sizeof(struct zt_chan) * 31, GFP_KERNEL);
					if (wc->tspans[x]) {
						memset(wc->tspans[x], 0, sizeof(struct t4_span) + sizeof(struct zt_chan) * 31);
						wc->tspans[x]->spantype = TYPE_E1;
					}
				} else {
					wc->tspans[x] = kmalloc(sizeof(struct t4_span) + sizeof(struct zt_chan) * 24, GFP_KERNEL);
					if (wc->tspans[x]) {
						memset(wc->tspans[x], 0, sizeof(struct t4_span) + sizeof(struct zt_chan) * 24);
						if (j1mode)
							wc->tspans[x]->spantype = TYPE_J1;
						else
							wc->tspans[x]->spantype = TYPE_T1;
					}
				}
				if (!wc->tspans[x])
					return -ENOMEM;
#ifdef ENABLE_WORKQUEUES
				INIT_WORK(&wc->tspans[x]->swork, workq_handlespan, wc->tspans[x]);
#endif				
				wc->tspans[x]->spanflags |= dt->flags;
			}


			/* Continue hardware intiialization */
			t4_hardware_init_2(wc);


#ifdef SUPPORT_GEN1
			if (request_irq(pdev->irq, (dt->flags & FLAG_2NDGEN) ? t4_interrupt_gen2 :t4_interrupt, SA_INTERRUPT | SA_SHIRQ, (wc->numspans == 2) ? "wct2xxp" : "wct4xxp", wc)) 
#else
			if (!(wc->tspans[0]->spanflags & FLAG_2NDGEN)) {
				printk("This driver does not support 1st gen modules\n");
				kfree(wc);
				return -ENODEV;
			}	
			if (request_irq(pdev->irq, t4_interrupt_gen2, SA_INTERRUPT | SA_SHIRQ, "t4xxp", wc)) 
#endif
			{
				printk("t4xxp: Unable to request IRQ %d\n", pdev->irq);
				kfree(wc);
				return -EIO;
			}

			init_spans(wc);

			/* Launch cards as appropriate */
			x = 0;
			for(;;) {
				/* Find a card to activate */
				f = 0;
				for (x=0;cards[x];x++) {
					if (cards[x]->order <= highestorder) {
						t4_launch(cards[x]);
						if (cards[x]->order == highestorder)
							f = 1;
					}
				}
				/* If we found at least one, increment the highest order and search again, otherwise stop */
				if (f) 
					highestorder++;
				else
					break;
			}

			printk("Found a Wildcard: %s\n", wc->variety);
			res = 0;
		} else
			res = -ENOMEM;
	}
	return res;
}

static int t4_hardware_stop(struct t4 *wc)
{

	/* Turn off DMA, leave interrupts enabled */
	wc->dmactrl = 0x0000000;
	t4_pci_out(wc, WC_DMACTRL, wc->dmactrl);	/* Turn on only the read interrupts, not the write */
	t4_pci_out(wc, WC_DMACTRL, wc->dmactrl);
	t4_pci_out(wc, WC_INTR, 0x00000000);

	current->state = TASK_UNINTERRUPTIBLE;
	schedule_timeout((25 * HZ) / 1000);

	/* Turn off counter, address, etc */
	if (wc->tspans[0]->spanflags & FLAG_2NDGEN) {
		t4_tsi_reset(wc);
	} else {
		t4_pci_out(wc, WC_COUNT, 0x000000);
	}
	t4_pci_out(wc, WC_RDADDR, 0x0000000);
	t4_pci_out(wc, WC_WRADDR, 0x0000000);
	t4_pci_out(wc, WC_GPIO, 0x0000000);
	t4_pci_out(wc, WC_LEDS, 0x00000000);

	printk("\nStopped TE%dXXP, Turned off DMA\n", wc->numspans);
	return 0;
}

static void __devexit t4_remove_one(struct pci_dev *pdev)
{
	struct t4 *wc = pci_get_drvdata(pdev);
	int x;
	if (wc) {
		/* Stop hardware */
		t4_hardware_stop(wc);

		/* Unregister spans */
		if (wc->tspans[0]->span.flags & ZT_FLAG_REGISTERED)
			zt_unregister(&wc->tspans[0]->span);
		if (wc->tspans[1]->span.flags & ZT_FLAG_REGISTERED)
			zt_unregister(&wc->tspans[1]->span);
		if (wc->numspans == 4) {
			if (wc->tspans[2]->span.flags & ZT_FLAG_REGISTERED)
				zt_unregister(&wc->tspans[2]->span);
			if (wc->tspans[3]->span.flags & ZT_FLAG_REGISTERED)
				zt_unregister(&wc->tspans[3]->span);
		}
#ifdef ENABLE_WORKQUEUES
		if (wc->workq) {
			flush_workqueue(wc->workq);
			destroy_workqueue(wc->workq);
		}
#endif			
#if 0
		/* Stop any DMA */
		__t1xxp_stop_dma(wc);

		/* In case hardware is still there */
		__t1xxp_disable_interrupts(wc);
		
		t1xxp_stop_stuff(wc);
#endif

		if (wc->membase)
			iounmap((void *)wc->membase);

		pci_release_regions(pdev);		
#if 0
		if (wc->memaddr)
			release_mem_region(wc->memaddr, wc->memlen);
#endif

		/* Immediately free resources */
		pci_free_consistent(pdev, ZT_MAX_CHUNKSIZE * 2 * 2 * 32 * 4, (void *)wc->writechunk, wc->writedma);
#if 1
		free_irq(pdev->irq, wc);
#endif		
		cards[wc->num] = NULL;
		pci_set_drvdata(pdev, NULL);
		for (x=0;x<wc->numspans;x++) {
			if (wc->tspans[x])
				kfree(wc->tspans[x]);
		}
		kfree(wc);
	}
}


static struct pci_device_id t4_pci_tbl[] __devinitdata =
{
	{ 0x10ee, 0x0314, PCI_ANY_ID, PCI_ANY_ID, 0, 0, (unsigned long)&wct4xxp },
	{ 0xd161, 0x0410, PCI_ANY_ID, PCI_ANY_ID, 0, 0, (unsigned long)&wct410p2 },
	{ 0xd161, 0x0405, PCI_ANY_ID, PCI_ANY_ID, 0, 0, (unsigned long)&wct405p2 },
	{ 0xd161, 0x0205, PCI_ANY_ID, PCI_ANY_ID, 0, 0, (unsigned long)&wct205 },
	{ 0xd161, 0x0210, PCI_ANY_ID, PCI_ANY_ID, 0, 0, (unsigned long)&wct210 },
	{ 0, }
};

static struct pci_driver t4_driver = {
	name: 	"Unified t4xxp/t2xxp driver",
	probe: 	t4_init_one,
#ifdef LINUX26
	remove:	__devexit_p(t4_remove_one),
#else
	remove:	t4_remove_one,
#endif
	suspend: NULL,
	resume:	NULL,
	id_table: t4_pci_tbl,
};

static int __init t4_init(void)
{
	int res;
	res = pci_module_init(&t4_driver);
	if (res)
		return -ENODEV;
	return 0;
}

static void __exit t4_cleanup(void)
{
	pci_unregister_driver(&t4_driver);
}


MODULE_AUTHOR("Mark Spencer");
MODULE_DESCRIPTION("Unified TE4XXP/TE2XXP PCI Driver");
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif
#ifdef LINUX26
module_param(debug, int, 0600);
module_param(loopback, int, 0600);
module_param(noburst, int, 0600);
module_param(timingcable, int, 0600);
module_param(t1e1override, int, 0600);
module_param(alarmdebounce, int, 0600);
module_param(j1mode, int, 0600);
module_param(debugslips, int, 0600);
module_param(polling, int, 0600);
#else
MODULE_PARM(debug, "i");
MODULE_PARM(loopback, "i");
MODULE_PARM(noburst, "i");
MODULE_PARM(debugslips, "i");
MODULE_PARM(polling, "i");
MODULE_PARM(timingcable, "i");
#ifdef VPM_SUPPORT
MODULE_PARM(vpmsupport,"i");
#endif
MODULE_PARM(t1e1override, "i");
MODULE_PARM(alarmdebounce, "i");
MODULE_PARM(j1mode, "i");
#endif

MODULE_DEVICE_TABLE(pci, t4_pci_tbl);

module_init(t4_init);
module_exit(t4_cleanup);

