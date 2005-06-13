/*
 * Real Time Clock interface of ADI21535 (Blackfin) for uCLinux 
 *
 * Copyright (C) 2003 Motorola Corporation.  All rights reserved.
 * 				Richard Xiao (A2590C@email.mot.com)
 *
 * Copyright (C) 1996 Paul Gortmaker
 *
 *	Based on other minimal char device drivers, like Alan's
 *	watchdog, Ted's random, etc. etc.
 *
 *	1.07	Paul Gortmaker.
 *	1.08	Miquel van Smoorenburg: disallow certain things on the
 *		DEC Alpha as the CMOS clock is also used for other things.
 *	1.09	Nikita Schmidt: epoch support and some Alpha cleanup.
 *	1.09a	Pete Zaitcev: Sun SPARC
 *	1.09b	Jeff Garzik: Modularize, init cleanup
 *	1.09c	Jeff Garzik: SMP cleanup
 *	1.10    Paul Barton-Davis: add support for async I/O
 *	1.10a	Andrea Arcangeli: Alpha updates
 *	1.10b	Andrew Morton: SMP lock fix
 *	1.10c	Cesar Barros: SMP locking fixes and cleanup
 *	1.10d	Paul Gortmaker: delete paranoia check in rtc_exit
 *	1.10e   LG Soft India: Register access is different in BF533. 	
 */

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/rtc.h>

#include <asm/irq.h>
#include <asm/blackfin.h>
#include "blackfin_rtc.h"

#define RTC_VERSION "1.10e"
#define RTC_IO_EXTENT   0x10    /* Only really two ports, but...    */

#undef RTC_DEBUG

#ifndef RTC_IRQ
#define RTC_IRQ		IRQ_RTC
#endif

/*
 * to_tm() converts system time back to (year, mon, day, hour, min, sec).
 * It is intended to help implement rtc_set_time() functions.
 * Copied from PPC implementation.
 */
extern void to_tm(unsigned long tim, struct rtc_time *tm);

/*
 *  We sponge a minor off of the misc major. No need slurping
 *  up another valuable major dev number for this. If you add
 *  an ioctl, make sure you don't conflict with SPARC's RTC
 *  ioctls.
 */
struct rtc_time rtc_timer;
extern spinlock_t rtc_lock;

static struct fasync_struct *rtc_async_queue;
static DECLARE_WAIT_QUEUE_HEAD(rtc_wait);
static struct timer_list rtc_irq_timer;

static loff_t rtc_llseek(struct file *file, loff_t offset, int origin);
static ssize_t rtc_read(struct file *file, char *buf,
            size_t count, loff_t *ppos);
static int rtc_ioctl(struct inode *inode, struct file *file,
             unsigned int cmd, unsigned long arg);

static unsigned int rtc_poll(struct file *file, poll_table *wait);
static void get_rtc_time (struct rtc_time *rtc_tm);
static void get_rtc_alm_time (struct rtc_time *alm_tm);

static void rtc_dropped_irq(unsigned long data);
static void set_rtc_irq_bit(unsigned char bit);
static void mask_rtc_irq_bit(unsigned char bit);

static inline unsigned char rtc_is_updating(void);

static int rtc_read_proc(char *page, char **start, off_t off,
                         int count, int *eof, void *data);
/*
 *  Bits in rtc_status. (6 bits of room for future expansion)
 */

#define RTC_IS_OPEN         0x01    /* means /dev/rtc is in use */
#define RTC_TIMER_ON        0x02    /* missed irq timer active  */

/*
 * rtc_status is never changed by rtc_interrupt, and ioctl/open/close is
 * protected by the big kernel lock. However, ioctl can still disable the timer
 * in rtc_status and then with del_timer after the interrupt has read
 * rtc_status but before mod_timer is called, which would then reenable the
 * timer (but you would need to have an awful timing before you'd trip on it)
 */
static unsigned long rtc_status = 0;    /* bitmapped status byte.   */
static unsigned long rtc_freq = 0;  /* Current periodic IRQ rate    */
static unsigned long rtc_irq_data = 0;  /* our output to the world  */

/*
 *  If this driver ever becomes modularised, it will be really nice
 *  to make the epoch retain its value across module reload...
 */

static unsigned long epoch = 2000;  /* year corresponding to 0x00   */

static unsigned long g_year = 0;
static unsigned long g_mon = 0;
static unsigned long g_alarm_day = 0;

static unsigned long g_last_day = 0;

static const unsigned char days_in_mo[] = 
{0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

static inline void wait_for_complete(void)
{
	unsigned long st;

check:
	st = *pRTC_ISTAT;
    	if((st & 0x8000) == 0)
		goto check;
    *(volatile unsigned short *)RTC_ISTAT |= 0x8000;
}

/*
 *  A very tiny interrupt handler. It runs with SA_INTERRUPT set,
 *  but there is possibility of conflicting with the set_rtc_mmss()
 *  call (the rtc irq and the timer irq can easily run at the same
 *  time in two different CPUs). So we need to serializes
 *  accesses to the chip with the rtc_lock spinlock that each
 *  architecture should implement in the timer code.
 *  (See ./arch/XXXX/kernel/time.c for the set_rtc_mmss() function.)
 */

static irqreturn_t rtc_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    /*
     *  Can be an alarm interrupt, update complete interrupt,
     *  or a periodic interrupt. We store the status in the
     *  low byte and the number of interrupts received since
     *  the last read in the remainder of rtc_irq_data.
     */
    unsigned long day;
    unsigned long cur_stat;
    int leap_yr1;
    int mon2; 
    
#ifdef RTC_DEBUG
printk("rtc_interrupt\n");
#endif
    
    spin_lock (&rtc_lock);
    rtc_irq_data += 0x1000;
    rtc_irq_data &= ~0xffff;

    /*rtc_irq_data |= (ADSP_RTC_READ(RTC_ISTAT) & 0x0fff);
      Does there need to clear the day alram flag ???
      rtc_irq_data |= (ADSP_RTC_READ(RTC_ISTAT) & 0x001f);
      Clear the H24 event flag ???*/
	rtc_irq_data |= (*pRTC_ISTAT & 0x000f);
	
    
	*pRTC_ISTAT = *pRTC_ISTAT;
	asm("ssync;");

    if (rtc_status & RTC_TIMER_ON)
        mod_timer(&rtc_irq_timer, jiffies + HZ/rtc_freq + 2*HZ/100);

    /* update the global year, month, and RTC-day */
    if(rtc_irq_data & H24_EVT_FG)   {
	cur_stat = *pRTC_STAT;
        day = (cur_stat>>24) & 0xff;

        mon2 = 0;
        leap_yr1 = ((!(g_year % 4) && (g_year % 100)) || !(g_year % 400));
        if((g_mon == 1) && leap_yr1)
            mon2 = 1;

        if((day-g_last_day) >= (days_in_mo[g_mon+1] + mon2))    {
            if((255 - day) <= 31)   {
                day = 0;
            }
            g_last_day = day;
            g_mon ++;
            if(g_mon >= 12) {
                g_year ++;
                g_mon = 0;
            }
            if(day == 0)    {
                cur_stat = (cur_stat&0x00ffffff);
		*pRTC_STAT = cur_stat;
                wait_for_complete();
            }
        }
    }
    
    spin_unlock (&rtc_lock);
    
    /* Now do the rest of the actions */
    wake_up_interruptible(&rtc_wait);   
    kill_fasync (&rtc_async_queue, SIGIO, POLL_IN);
    return IRQ_HANDLED;
}

/*
 *  Now all the various file operations that we export.
 */

static loff_t rtc_llseek(struct file *file, loff_t offset, int origin)
{
    return -ESPIPE;
}

static ssize_t rtc_read(struct file *file, char *buf,
            size_t count, loff_t *ppos)
{
    DECLARE_WAITQUEUE(wait, current);
    unsigned long data;
    ssize_t retval;
    
    if (count < sizeof(unsigned long))
        return -EINVAL;

    add_wait_queue(&rtc_wait, &wait);

    current->state = TASK_INTERRUPTIBLE;
        
    do {
        /* First make it right. Then make it fast. Putting this whole
         * block within the parentheses of a while would be too
         * confusing. And no, xchg() is not the answer. */
        spin_lock_irq (&rtc_lock);
        data = rtc_irq_data;
        rtc_irq_data = 0;
        spin_unlock_irq (&rtc_lock);

        if (data != 0)
            break;

        if (file->f_flags & O_NONBLOCK) {
            retval = -EAGAIN;
            goto out;
        }
        if (signal_pending(current)) {
            retval = -ERESTARTSYS;
            goto out;
        }
        schedule();
    } while (1);

    retval = put_user(data, (unsigned long *)buf); 
    if (!retval)
        retval = sizeof(unsigned long); 
 out:
    current->state = TASK_RUNNING;
    remove_wait_queue(&rtc_wait, &wait);

    return retval;
}

static int rtc_ioctl(struct inode *inode, struct file *file, unsigned int cmd,
             unsigned long arg)
{
    struct rtc_time wtime; 
    unsigned long swcnt;
    unsigned short swcnttm;

    switch (cmd) {
	/* stop watch interrupt*/
    case RTC_SWCNT_OFF: /* mask stop watch int. enab. bit */
    {
        mask_rtc_irq_bit(STPW_INT_EN);
        return 0;
    }
    case RTC_SWCNT_ON:
    {
	spin_lock_irq(&rtc_lock);
	*pRTC_ICTL |= STPW_INT_EN;
	asm("SSYNC;");
	wait_for_complete();
	spin_unlock_irq(&rtc_lock);
        //set_rtc_irq_bit(STPW_INT_EN);
        return 0;
    }

    case RTC_AIE_OFF:   /* Mask alarm int. enab. bit    */
    {
        mask_rtc_irq_bit(ALM_INT_EN);
        return 0;
    }
    case RTC_AIE_ON:    /* Allow alarm interrupts.  */
    {
        set_rtc_irq_bit(ALM_INT_EN);
        return 0;
    }

    case RTC_UIE_OFF:   /* Mask ints from RTC updates.  */
    {
        mask_rtc_irq_bit(SEC_INT_EN);//???
        return 0;
    }
    case RTC_UIE_ON:    /* Allow ints for RTC updates.  */
    {
        set_rtc_irq_bit(SEC_INT_EN);
        return 0;
    }
    case RTC_ALM_READ:  /* Read the present alarm time */
    {
        /*
         * This returns a struct rtc_time. Reading >= 0xc0
         * means "don't care" or "match all". Only the tm_hour,
         * tm_min, and tm_sec values are filled in.
         */
        get_rtc_alm_time(&wtime);
        break; 
    }
    case RTC_ALM_SET:   /* Store a time into the alarm */
    {
        /*
         * This expects a struct rtc_time. Writing 0xff means
         * "don't care" or "match all". Only the tm_hour,
         * tm_min and tm_sec are used.
         */
        unsigned char hrs, min, sec;
        unsigned int day;
        struct rtc_time alm_tm;

        if (copy_from_user(&alm_tm, (struct rtc_time*)arg,
                   sizeof(struct rtc_time)))
            return -EFAULT;

        /* in fact, the day alarm setting is no used */
        day = alm_tm.tm_mday;
        hrs = alm_tm.tm_hour;
        min = alm_tm.tm_min;
        sec = alm_tm.tm_sec;

        if (day >= 256)
            day = 0x0;

        if (hrs >= 24)
            hrs = 0x0;

        if (min >= 60)
            min = 0x0;

        if (sec >= 60)
            sec = 0x0;
            
        /*save the alarm day*/          
        g_alarm_day = day;
        
        spin_lock_irq(&rtc_lock);

        *pRTC_ALARM = ((g_alarm_day<<DAY_BITS_OFF) | (hrs<<HOUR_BITS_OFF) | (min<<MIN_BITS_OFF)
                       | (sec<<SEC_BITS_OFF));
        wait_for_complete();

        spin_unlock_irq(&rtc_lock);

        return 0;
    }
    case RTC_RD_TIME:   /* Read the time/date from RTC  */
    {
        get_rtc_time(&wtime);
        break;
    }
    case RTC_SET_TIME:  /* Set the RTC */
    {
        struct rtc_time rtc_tm;
        unsigned char mon, day, hrs, min, sec, leap_yr;
        unsigned int yrs;

        if (!capable(CAP_SYS_TIME)) 
            return -EACCES;

        if (copy_from_user(&rtc_tm, (struct rtc_time*)arg,
                   sizeof(struct rtc_time)))
            return -EFAULT;

        yrs = rtc_tm.tm_year + epoch;
        mon = rtc_tm.tm_mon + 1;   /* tm_mon starts at zero */
        day = rtc_tm.tm_mday;
        hrs = rtc_tm.tm_hour;
        min = rtc_tm.tm_min;
        sec = rtc_tm.tm_sec;

        leap_yr = ((!(yrs % 4) && (yrs % 100)) || !(yrs % 400));

        if ((mon > 12) || (day == 0))   {
            return -EINVAL;
        }
        if (day > (days_in_mo[mon] + ((mon == 2) && leap_yr)))
            return -EINVAL;
            
        if ((hrs >= 24) || (min >= 60) || (sec >= 60))
            return -EINVAL;

        if ((yrs -= epoch) > 255)    /* They are unsigned */	
            return -EINVAL;

        /*save the year and month*/     

        if (yrs >= 100)
            yrs -= 100;

        g_year = epoch + yrs ;

        g_mon =  mon - 1;

        day --;
        g_last_day = 0;
        
        spin_lock_irq(&rtc_lock);
        *pRTC_STAT = ((day<<DAY_BITS_OFF) | (hrs<<HOUR_BITS_OFF) | (min<<MIN_BITS_OFF)
                       | (sec<<SEC_BITS_OFF));
        wait_for_complete();
                   
        spin_unlock_irq(&rtc_lock);
        return 0;
    }

/* do not support periodic*/
    case RTC_IRQP_READ: /* Read the periodic IRQ rate.  */
    {
        return put_user(rtc_freq, (unsigned long *)arg);
    }
    case RTC_IRQP_SET:  /* Set periodic IRQ rate to rtc_freq */
    {
        int tmp = 0;

        /* 
         * The max we can do is 8192Hz.
         */
        if ((arg < 2) || (arg > 8192))
            return -EINVAL;
        /*
         * We don't really want Joe User generating more
         * than 64Hz of interrupts on a multi-user machine.
         */
        if ((arg > 64) && (!capable(CAP_SYS_RESOURCE)))
            return -EACCES;

        while (arg > (1<<tmp))
            tmp++;

        /*
         * Check that the input was really a power of 2.
         */
        if (arg != (1<<tmp))
            return -EINVAL;

        spin_lock_irq(&rtc_lock);
        rtc_freq = arg;

        spin_unlock_irq(&rtc_lock);
        return 0;
    }
    case RTC_EPOCH_READ:    /* Read the epoch.  */
    {
        return put_user (epoch, (unsigned long *)arg);
    }
    case RTC_EPOCH_SET: /* Set the epoch.   */
    {
        /* 
         * There were no RTC clocks before 1900.
         */
        if (arg < 2000)
            return -EINVAL;

        epoch = arg - (arg%100);
        g_year = epoch + (g_year%100);

        return 0;
    }

    case RTC_SWCNT_SET: /* Read the periodic IRQ rate.  */
    {
	copy_from_user(&swcnttm, (unsigned long *)&arg, sizeof(unsigned long));

    	spin_lock_irq(&rtc_lock);
	*pRTC_SWCNT = swcnttm;
	asm("SSYNC;");
	wait_for_complete();
	spin_unlock_irq(&rtc_lock);
	return 0;	
    }
    case RTC_SWCNT_RD:  /* Set periodic IRQ rate.   */
    {
	swcnt = *pRTC_SWCNT;
        return put_user (swcnt, (unsigned long *)arg);
    }
    
    default:
        return -EINVAL;
    }
    return copy_to_user((void *)arg, &wtime, sizeof wtime) ? -EFAULT : 0;
}

/*
 *  We enforce only one user at a time here with the open/close.
 *  Also clear the previous interrupt data on an open, and clean
 *  up things on a close.
 */

/* We use rtc_lock to protect against concurrent opens. So the BKL is not
 * needed here. Or anywhere else in this driver. */
static int rtc_open(struct inode *inode, struct file *file)
{
    spin_lock_irq (&rtc_lock);

    if(rtc_status & RTC_IS_OPEN)
        goto out_busy;

    rtc_status |= RTC_IS_OPEN;

    rtc_irq_data = 0;
    spin_unlock_irq (&rtc_lock);
    return 0;

out_busy:
    spin_unlock_irq (&rtc_lock);
    return -EBUSY;
}

static int rtc_fasync (int fd, struct file *filp, int on)

{
    return fasync_helper (fd, filp, on, &rtc_async_queue);
}

static int rtc_release(struct inode *inode, struct file *file)
{
    /*
     * Turn off all interrupts once the device is no longer
     * in use, and clear the data.
     */
    unsigned char tmp;

    spin_lock_irq(&rtc_lock);
    tmp = *pRTC_ICTL;
    tmp &=  ~STPW_INT_EN;
    tmp &=  ~ALM_INT_EN;
    tmp &=  ~SEC_INT_EN;
    tmp &=  ~MIN_INT_EN;
    tmp &=  ~DAY_INT_EN;
    tmp &=  ~WC_INT_EN;
    *pRTC_ICTL = tmp;
    wait_for_complete();

    if (rtc_status & RTC_TIMER_ON) {
        rtc_status &= ~RTC_TIMER_ON;
        del_timer(&rtc_irq_timer);
    }
    spin_unlock_irq(&rtc_lock);

    if (file->f_flags & FASYNC) {
        rtc_fasync (-1, file, 0);
    }
    spin_lock_irq (&rtc_lock);
    rtc_irq_data = 0;
    spin_unlock_irq (&rtc_lock);

    /* No need for locking -- nobody else can do anything until this rmw is
     * committed, and no timer is running. */
    rtc_status &= ~RTC_IS_OPEN;
    return 0;
}

/* Called without the kernel lock - fine */
static unsigned int rtc_poll(struct file *file, poll_table *wait)
{
    unsigned long l;

    spin_lock_irq (&rtc_lock);
    l = rtc_irq_data;
    spin_unlock_irq (&rtc_lock);

    if (l != 0)
        return POLLIN | POLLRDNORM;
    return 0;
}

/*
 *  The various file operations we support.
 */

static struct file_operations rtc_fops = {
    owner:      THIS_MODULE,
    llseek:     rtc_llseek,
    read:       rtc_read,
    poll:       rtc_poll,
    ioctl:      rtc_ioctl,
    open:       rtc_open,
    release:    rtc_release,
    fasync:     rtc_fasync
};

static struct miscdevice rtc_dev=
{
    RTC_MINOR,
    "rtc",
    &rtc_fops
};


int __init blackfin_rtc_init(void)
{
#ifdef RTC_DEBUG
    printk("blackfin_rtc_init\n");
#endif
    *pRTC_PREN = PRESCALE_EN;
    asm("ssync;");
    *pRTC_ISTAT = 0x807F;
    asm("ssync;");
    *pRTC_ICTL = 0x0;
    asm("ssync;");
    *pRTC_ALARM = 0;
    asm("ssync;");
    
    if(request_irq(RTC_IRQ, rtc_interrupt, SA_INTERRUPT, "rtc", NULL))
    {
        /* Yeah right, seeing as irq 8 doesn't even hit the bus. */
        printk(KERN_ERR "rtc: IRQ %d is not free.\n", RTC_IRQ);
        return -EIO;
    }

    misc_register(&rtc_dev);
    create_proc_read_entry ("driver/rtc", 0, 0, rtc_read_proc, NULL);

    init_timer(&rtc_irq_timer);
    rtc_irq_timer.function = rtc_dropped_irq;
    spin_lock_irq(&rtc_lock);
    spin_unlock_irq(&rtc_lock);
    rtc_freq = 1024;
    
    *pRTC_ICTL = H24_INT_EN;
    wait_for_complete();

    printk(KERN_INFO "Real Time Clock Driver v" RTC_VERSION "\n");

    return 0;
}

void __exit blackfin_rtc_exit (void)
{
    disable_irq(RTC_IRQ);
    remove_proc_entry ("driver/rtc", NULL);
    misc_deregister(&rtc_dev);
    free_irq (RTC_IRQ, NULL);
}

module_init(blackfin_rtc_init);
module_exit(blackfin_rtc_exit);

/*
 *  At IRQ rates >= 4096Hz, an interrupt may get lost altogether.
 *  (usually during an IDE disk interrupt, with IRQ unmasking off)
 *  Since the interrupt handler doesn't get called, the IRQ status
 *  byte doesn't get read, and the RTC stops generating interrupts.
 *  A timer is set, and will call this function if/when that happens.
 *  To get it out of this stalled state, we just read the status.
 *  At least a jiffy of interrupts (rtc_freq/HZ) will have been lost.
 *  (You *really* shouldn't be trying to use a non-realtime system 
 *  for something that requires a steady > 1KHz signal anyways.)
 */

static void rtc_dropped_irq(unsigned long data)
{
    unsigned long freq;

    spin_lock_irq (&rtc_lock);

    /* Just in case someone disabled the timer from behind our back... */
    if (rtc_status & RTC_TIMER_ON)
        mod_timer(&rtc_irq_timer, jiffies + HZ/rtc_freq + 2*HZ/100);

    rtc_irq_data += ((rtc_freq/HZ)<<8);
    rtc_irq_data &= ~0xffff;
    rtc_irq_data |= (*pRTC_STAT & 0xffff);    /* restart */
	

    freq = rtc_freq;

    spin_unlock_irq(&rtc_lock);

    printk(KERN_WARNING "rtc: lost some interrupts at %ldHz.\n", freq);

    /* Now we have new data */
    wake_up_interruptible(&rtc_wait);

    kill_fasync (&rtc_async_queue, SIGIO, POLL_IN);
}

/*
 *  Info exported via "/proc/driver/rtc".
 */

static int rtc_proc_output (char *buf)
{
    char *p;
    struct rtc_time tm;
    unsigned long freq;

    spin_lock_irq(&rtc_lock);
    freq = rtc_freq;
    spin_unlock_irq(&rtc_lock);

    p = buf;

    get_rtc_time(&tm);

    /*
     * There is no way to tell if the luser has the RTC set for local
     * time or for Universal Standard Time (GMT). Probably local though.
     */
    p += sprintf(p,
             "rtc_time\t: %02d:%02d:%02d\n"
             "rtc_date\t: %04d-%02d-%02d\n",
             tm.tm_hour, tm.tm_min, tm.tm_sec,
             tm.tm_year, tm.tm_mon + 1, tm.tm_mday);

    get_rtc_alm_time(&tm);

    /*
     * We implicitly assume 24hr mode here. Alarm values >= 0xc0 will
     * match any value for that particular field. Values that are
     * greater than a valid time, but less than 0xc0 shouldn't appear.
     */
    p += sprintf(p, "alarm\t\t: ");
    if (tm.tm_hour <= 24)
        p += sprintf(p, "%02d:", tm.tm_hour);
    else
        p += sprintf(p, "**:");

    if (tm.tm_min <= 59)
        p += sprintf(p, "%02d:", tm.tm_min);
    else
        p += sprintf(p, "**:");

    if (tm.tm_sec <= 59)
        p += sprintf(p, "%02d\n", tm.tm_sec);
    else
        p += sprintf(p, "**\n");

    return  p - buf;
}

static int rtc_read_proc(char *page, char **start, off_t off,
                         int count, int *eof, void *data)
{
        int len = rtc_proc_output (page);
        if (len <= off+count) *eof = 1;
        *start = page + off;
        len -= off;
        if (len>count) len = count;
        if (len<0) len = 0;
        return len;
}

/*
 * Returns true if a clock update is in progress
4/8/3 11:45AM */
static inline unsigned char rtc_is_updating(void)
{
    unsigned char uip;

    spin_lock_irq(&rtc_lock);
	uip = (*pRTC_STAT & SEC_EVT_FG);
    spin_unlock_irq(&rtc_lock);
    return uip;
}

static void get_rtc_time(struct rtc_time *rtc_tm)
{
    unsigned long cur_rtc_stat;
    /*
     * Only the values that we read from the RTC are set. We leave
     * tm_wday, tm_yday and tm_isdst untouched. Even though the
     * RTC has RTC_DAY_OF_WEEK, we ignore it, as it is only updated
     * by the RTC when initially set to a non-zero value.
     */
    spin_lock_irq(&rtc_lock);
    cur_rtc_stat = *pRTC_STAT;

    rtc_tm->tm_sec = (cur_rtc_stat>>SEC_BITS_OFF) & 0x3f;
    rtc_tm->tm_min = (cur_rtc_stat>>MIN_BITS_OFF) & 0x3f;
    rtc_tm->tm_hour = (cur_rtc_stat>>HOUR_BITS_OFF) & 0x1f;
    rtc_tm->tm_mday = (cur_rtc_stat>>DAY_BITS_OFF) & 0x7fff;

    rtc_tm->tm_mday -= g_last_day;
    rtc_tm->tm_mday ++;
    
    rtc_tm->tm_mon = g_mon;
    rtc_tm->tm_year = g_year;

    spin_unlock_irq(&rtc_lock);

    /*
     * Account for differences between how the RTC uses the values
     * and how they are defined in a struct rtc_time;
     */
}

static void get_rtc_alm_time(struct rtc_time *alm_tm)
{
    unsigned long cur_rtc_alarm;
    /*
     * Only the values that we read from the RTC are set. That
     * means only tm_hour, tm_min, and tm_sec.
     */
    spin_lock_irq(&rtc_lock);
    cur_rtc_alarm = *pRTC_ALARM;	
    alm_tm->tm_sec = (cur_rtc_alarm>>SEC_BITS_OFF) & 0x3f;
    alm_tm->tm_min = (cur_rtc_alarm>>MIN_BITS_OFF) & 0x3f;
    alm_tm->tm_hour = (cur_rtc_alarm>>HOUR_BITS_OFF) & 0x1f;
    alm_tm->tm_mday = (cur_rtc_alarm>>DAY_BITS_OFF) & 0x7fff;
    
    spin_unlock_irq(&rtc_lock);
}

/*
 * Used to disable/enable interrupts for any one of UIE, AIE, PIE.
 * Rumour has it that if you frob the interrupt enable/disable
 * bits in RTC_CONTROL, you should read RTC_INTR_FLAGS, to
 * ensure you actually start getting interrupts. Probably for
 * compatibility with older/broken chipset RTC implementations.
 * We also clear out any old irq data after an ioctl() that
 * meddles with the interrupt enable/disable bits.
 */

static void mask_rtc_irq_bit(unsigned char bit)
{
    unsigned char val;
    
    spin_lock_irq(&rtc_lock);
    val = *pRTC_ICTL;

    val &=  ~bit;
    *pRTC_ICTL = val;
    wait_for_complete();

    rtc_irq_data = 0;
    spin_unlock_irq(&rtc_lock);
}

static void set_rtc_irq_bit(unsigned char bit)
{
    unsigned char val;

    spin_lock_irq(&rtc_lock);
    val = *pRTC_ICTL;
    val |= bit;
    *pRTC_ICTL = val;
    wait_for_complete();

    rtc_irq_data = 0;
    spin_unlock_irq(&rtc_lock);
}
