/**************************************************************
*
* Copyright (C) 2005, Rubico AB. All Rights Reserve.
*
* Developed as a part the CDT project C4(www.cdt.ltu.se).
*
* FILE spi_mmc.c
*
* PROGRAMMER: Hans Eklund, hans [at] rubico [dot] se (Rubico AB, www.rubico.se)
*
* DATE OF CREATION: Jun. 30th 2006
*
* BASED ON: bfin_spi_mmc.c
*
* SYNOPSIS:
*
* DESCRIPTION: SPI-MMC/SD Block device Driver.
*
* DEPENDENCIES: 1) A bunch of kernel headers, 
*		2) mmc_spi_mode - platform independent layer for doing
*		communication with MMC over any SPI channel. It implements
*		the important parts of the MMC-SPI protocol.
*
* NOTE: - see http://www.vpx.nu/dokuwiki/doku.php?id=mmc_sd_configuration
*         for documentation on how to use this driver.
*       - Blackfin specific code are marked with #ifdef BFIN(or similar).
*	  Direct compilation on other platforms will fail.
*       - Card detection is optionally implemented for blackfin platforms
*         and could be disabled in kernel config. It could be further
*         developed to support hotplug events for userspace /sbin/hotplug
*
* TODO:	- Error handling and recovery(propagating spi and mmc errors
*		to block layer error handling and recovery).
*	- Performance, fix multiple block reads(less important)
*	- Tweaking queue parameters, blk_queue_max_...-functions
*	- Support for multiple instances of the driver on different
*		chip select signals for a stack of MMC/SDs.
*	- Could probably make better use of the spi framework for slightly
*	  better performance(read then write type of optimiz.)
*	- Nicer CSD registry parsing, let maximum clock depend on CSD
*         maximum speed. Better use of CSD information in general.
*	- If a media is removed and umount is performed. end_request will
*	  scream a bit. Could be nicer done probably.
*
* Oct,	2006 -	Fixed timeout issue in mmc_spi_mode.c. Added primitive error log
*		to /proc/spi_mmc.
* Oct,  2006 -	Improved support for SD cards. Simpler request processing for now
*		Fall back to single block writes if multiple writes fails. Added
*		low level performance monitor to /proc/spi_mmc. Minor
*		performance tweaks. A good(new) card can support 700 kB/sec reading
*		and writing with multiple block writes, not counting block layer
*		overhead. Several off-brand SDs works now. /Hans
* Oct,  2006 - 	Processing request on a dedicated work queue. Mode RM_FULL
*              	does not leave calling process DW(dead waiting) any more.
*	       	Minor Improvements to mmc_spi_mode.c. /Hans
* Aug,  2006 - 	Relies on common SPI framework now and very little BFIN code 
*              	Multiple Block Write operations is working.
*              	Several other improvements. /Hans
* June, 2006 - 	First release with lots of ADI Blackfin specific code. /Hans
*
*		The following cards were successfully formated with mke2fs utility:
*
*		> Kingston MMC+ 1GB.
*		> Integral MMC 64 MB.
*		> TwinMOS MMC 128 MB.
*		> MemoryCorp 256MB SD.
*		> Kingston MMC mobile 256 MB.
*		> Kingston 256 MB SD.
*		> Kingston 128 MB MMC.
*		> SanDisk 256 MB SD.
*
*	       A few were tested with full read/write badblocks test. 
*
**************************************************************
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
**************************************************************/
#include <linux/config.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/kernel.h>	/* printk() */
#include <linux/slab.h>		/* kmalloc() */
#include <linux/fs.h>		/* everything... */
#include <linux/errno.h>	/* error codes */
#include <linux/timer.h>
#include <linux/types.h>	/* size_t */
#include <linux/fcntl.h>	/* O_ACCMODE */
#include <linux/hdreg.h>	/* HDIO_GETGEO */
#include <linux/kdev_t.h>
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>	/* invalidate_bdev */
#include <linux/bio.h>
#include <linux/string.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/mmc/card.h>
#include <linux/spi/spi.h>

// Blackfin Dependencies
#ifdef CONFIG_BFIN
#include <asm/blackfin.h>
#include <asm/cacheflush.h>
#endif

// Close dependencies
#include "mmc_spi_mode.h"
#include "spi_mmc_core.h"

MODULE_LICENSE("GPL");

#define __DRIVER_AUTHOR	 	"Hans Eklund(hans@rubico.se)"
#define SPI_MMC_DEVNAME		"spi_mmc"
#define SPI_MMC_DUMMY_DEVNAME	"spi_mmc_dummy"

#ifdef CONFIG_SPI_MMC_DEBUG_MODE
	#define DPRINTK(x...)   printk("%lu, %s(): %d ", jiffies, __PRETTY_FUNCTION__, __LINE__);printk(x);
#else
	#define DPRINTK(x...)	do { } while (0)
#endif 

// Kconfig parameters
#ifndef CONFIG_SPI_MMC_CS_CHAN
#define CONFIG_SPI_MMC_CS_CHAN	4
#endif

#ifndef CONFIG_SPI_MMC_CARD_DETECT_PFLAG
#define CARD_DETECT_IRQ (IRQ_PF0 + 5)
#else 
#define CARD_DETECT_IRQ (IRQ_PF0 + CONFIG_SPI_MMC_CARD_DETECT_PFLAG)
#endif

// some magic numbers for the spi mmc core
enum {
	GEO_HEADS			= 4,		/* Phony device geometry numbers*/
	GEO_SECTORS			= 16,		/* ... */
	KERNEL_SECTOR_SIZE 		= 512,		/* scale MMC sectors with this(if other than 512)*/
	MAJOR_NUMBER			= 36,		/* or whatever your system works with */
	MINORS				= 4,		/* how many minor devices(partitions) */
	MBW_ALLOWED			= 1,		/* if Multiple Block Write(MBW) command is allowed */
	MULTIPLE_BLOCK_WRITE_TRESH	= 1,		/* when to use MBW instead of SBW commands */
	XFER_RETRY_LIMIT		= 3,		/* how many time to retry single block operations */
	MMC_SD_INIT_RETRIES		= 0,		/* how many times to run the init cycle */
	SPI_CLOCK_INIT_HZ		= 400000,	/* MMC spec. says this is the clock for init */
	SPI_CLOCK_MAX_HZ		= 20000000,	/* until MAX_HZ is found in MMC/SD CSD register */
	CARD_DETECT_INTERVAL		= 400,		/* msec. interval between card detection */
	MAX_ERRORS_BEFORE_NUKE		= 3
};

static DECLARE_MUTEX(card_sema);
static DECLARE_WORK(card_work, NULL, NULL);
static DECLARE_WORK(transfer_work, NULL, NULL);

static mmc_info_t* Devices;
static int spi_mmc_card_init(mmc_info_t* pdev);
static int spi_mmc_dev_init(mmc_info_t* pdev);
static int spi_mmc_revalidate(struct gendisk *gd);
unsigned char* k_buffer;

static struct spi_device *dummy_spi;

/*
 * The different "request modes" we can use.
 */
enum {
	RM_FULL    = 1,	/* The full-blown version using strategy function*/
	RM_NOQUEUE = 2,	/* Use make_request(simple) */
};
static int request_mode = RM_FULL;

/**********************************************************************\
*
* Low level helpers, borrowed from bfin_spi_adc.c by Michael Hennerich.
*
\**********************************************************************/
#ifdef CONFIG_BFIN
static u_long get_vco(void)
{
	u_long vco;
	vco = (CONFIG_CLKIN_HZ) * ((bfin_read_PLL_CTL() >> 9)& 0x3F);

	if (1 & bfin_read_PLL_CTL()) /* DR bit */
		vco >>= 1;

	return vco;
}


static u_long spi_get_sclk(void)
{
	u_long vco;
	u_long sclk = 0;

	vco = get_vco();

	if((bfin_read_PLL_DIV() & 0xf) != 0)
		sclk = vco/(bfin_read_PLL_DIV() & 0xf);
	else
		printk(KERN_NOTICE "bfin_spi_adc: Invalid System Clock\n");

	return (sclk);
}
#endif

/**********************************************************************\
*
* Block device layer. (Requests to transfer layer.)
*
\**********************************************************************/

/*
 * Function:    spi_mmc_transfer()
 *
 * Purpose:     Transfer a number of consecutive sectors using a suitable
 *		MMC command.
 *
 * Arguments:   pdev	- device structure
 *              sector	- first sector to transfer
 *		nsect	- number of sectors to transfer
 *		buffer	- pointer to buffer to retrieve or put data
 *		write	- true for write operation, false for read
 *		
 * Lock status: Assumed that lock is not held upon entry.
 *
 * Returns:     0 for OK, any other number is an error
 *
 * Notes:	
 *
 */
static short spi_mmc_transfer(mmc_info_t *pdev, unsigned long sector, unsigned long nsect, char *buffer, int write)
{
	unsigned long offset = sector * KERNEL_SECTOR_SIZE;
	unsigned int nsect_xf=0;
	short  rval=0;
	short retry_flag=0;
	
	down_interruptible(&card_sema);
	pdev->pi.last_block = offset;
	
	/* Multiple write block operations */
	if((nsect >= MULTIPLE_BLOCK_WRITE_TRESH) && MBW_ALLOWED && write && pdev->pi.mbw_works) {
		if(mmc_spi_write_mult_mmc_block(&(pdev->msd), buffer, offset, nsect)) {
			// dont use MBW anymore, go on to single block writes
			pdev->pi.mbw_works=0;
		} else {
			goto out;
		}
	}
	/* Run block transfers individually */
	while(nsect_xf < nsect) {
		retry_flag=0;
		retry:
		if(write) {
			rval=mmc_spi_write_mmc_block(&(pdev->msd), buffer+(nsect_xf * KERNEL_SECTOR_SIZE), offset+(nsect_xf * KERNEL_SECTOR_SIZE) );
		} else {
			rval=mmc_spi_read_mmc_block(&(pdev->msd), buffer+(nsect_xf * KERNEL_SECTOR_SIZE), offset+(nsect_xf * KERNEL_SECTOR_SIZE) );
		}
		if(rval) {
			if(retry_flag < XFER_RETRY_LIMIT) {
				retry_flag++;
				goto retry;
			}
			// return if error
			goto out;
		}
		nsect_xf++;
	}
	out:		
	up(&card_sema);

	return rval;
}

static void spi_mmc_process_request(mmc_info_t *pdev, struct request *req)
{
	int uptodate;
	int status;
	int sectors_xferred;
	unsigned long j1;
	unsigned long j2;
	unsigned long d;
	unsigned long t_msec;
	unsigned long throughput;

	uptodate = 1;
	sectors_xferred=0;

	j1=jiffies;
	status = spi_mmc_transfer(pdev, req->sector, req->current_nr_sectors, req->buffer, rq_data_dir(req));
	j2=jiffies;
	// skip if jiffies counter flipped around
	if(j2<=j1)
		goto skip;
	d=jiffies-j1;			// [jiffies]
	t_msec = ( d * 1000 )/ HZ;	// [ms]
	throughput = (KERNEL_SECTOR_SIZE * req->current_nr_sectors) / t_msec; // b/msec = [kb/sec] (range 0-2000)
	// ARMA filter over 100 last measures since throughput is very rough.
	if(rq_data_dir(req)) {
		pdev->pi.mean_write_tp = (99 * pdev->pi.mean_write_tp + throughput) / 100;
	} else {
		pdev->pi.mean_read_tp = (99 * pdev->pi.mean_read_tp + throughput) / 100;
	}
	skip:

	//printk("tp: %u kb/sec based on %u jiffies, mean: %u kb/sec\n", throughput, d, m);

	// simple, just set the request number of sectors to finish below.
	sectors_xferred = req->current_nr_sectors;

	switch(status) {
		case 0:
			uptodate = 1;
			break;
		default:
			// any other kind of error, try to re-init card
			spi_mmc_revalidate(pdev->gd);
			uptodate = 0;
	}

	spin_lock(&pdev->queue_lock);
	if(!end_that_request_first(req, uptodate, sectors_xferred)) {
		add_disk_randomness(req->rq_disk);
		blkdev_dequeue_request(req);
		end_that_request_last(req, uptodate);
	}
	spin_unlock(&pdev->queue_lock);
}


/*
 * Function:    spi_mmc_transfer_worker()
 *
 * Purpose:	Entry point for walking the request queue on
 *		a work queue
 *
 * Arguments:   arg that is the device structure mmc_info_t
 *		
 * Lock status: Nothing
 *
 * Returns:     Nothing
 *
 * Notes:	
 *
 */
static void spi_mmc_transfer_worker(void* arg)
{
	mmc_info_t *pdev;
	struct request *req;
	request_queue_t *q;

	// cast void* argument
	pdev = (mmc_info_t*)arg;
	req = pdev->current_req;
	q = pdev->gd->queue;

	// assumes that a request is assigned upon entry
	while(1) {

		if(req == NULL) {
			return;
		}
		if (!blk_fs_request(req)) {
			DPRINTK(KERN_NOTICE "Skip non-fs request\n");
			spin_lock(&pdev->queue_lock);
			end_request(req, 0);
			spin_unlock(&pdev->queue_lock);
		} 
		if(pdev->card_in_bay) {
			pdev->current_req = req;
			spi_mmc_process_request(pdev, req);
		} else {
			// NOTE:
			// no card/dead card.. just end and go on. Could start some kind of
			// polling for the device to try re-init and not end request right now.
			// since the device is offline, this will become a nuking loop of the
			// remaining requests, nicer way to solve this?
			spin_lock(&pdev->queue_lock);
			end_request(req, 0);
			spin_unlock(&pdev->queue_lock);
		} 

		// grab the next request and continue
		spin_lock(&pdev->queue_lock);
		req = elv_next_request(q);
		spin_unlock(&pdev->queue_lock);
	}
}

/*
 * Function:    spi_mmc_strategy()
 *
 * Purpose:     Strategy function that simply starts the request processing on a work queue
 *
 * Arguments:   q	- the address to reqeust queue given by the I/O scheduler
 *		
 * Lock status: Assumed that lock is not held upon entry.
 *
 * Returns	nothing
 *
 * Notes:	
 *
 */
static void spi_mmc_strategy(request_queue_t *q)
{
	mmc_info_t* pdev = (mmc_info_t*)q->queuedata;

	// elevate first request from the dispatch queue
	spin_lock(&pdev->queue_lock);
	pdev->current_req = elv_next_request(q);
	spin_unlock(&pdev->queue_lock);

	if(pdev->current_req == NULL)
		return;
	
	// process rest of the dispatch queue on a dedicated kernel thread
	schedule_work(&transfer_work);
}

static int spi_mmc_xfer_bio(mmc_info_t *pdev, struct bio *bio)
{
	int i;
	int error = 0;
	struct bio_vec *bvec;
	sector_t sector = bio->bi_sector;

	/* do each segment independently */
	bio_for_each_segment(bvec, bio, i) {
		unsigned char *buffer = __bio_kmap_atomic(bio, i, KM_USERo);
		if(pdev->card_in_bay) {
			error = spi_mmc_transfer(pdev, sector, bio_cur_sectors(bio),
				 buffer, bio_data_dir(bio) == WRITE);
		} else {
			// Just return with error if card was pulled from socket
			__bio_kunmap_atomic(bio, KM_USERo);
			return -EIO;
		}
		// On error, check if card is still present in socket
		// if so, try next sector
		if(error) {
			if(spi_mmc_dev_init(pdev)) {
				pdev->card_in_bay = 0;
			}			
		}
		sector += bio_cur_sectors(bio);
		__bio_kunmap_atomic(bio, KM_USERo);
	}
	return error;
}

static int spi_mmc_make_request(request_queue_t *q, struct bio *bio)
{
	mmc_info_t *pdev = q->queuedata;
	int error;

	error = spi_mmc_xfer_bio(pdev, bio);
	bio_endio(bio, bio->bi_size, error);
	return 0;
}

/**********************************************************************\
*
* SPI-MMC callbacks
*
\**********************************************************************/
static int write_func(unsigned char *buf, unsigned int count, void* priv_data) 
{
	struct spi_transfer t;
	struct spi_message m;
	mmc_info_t *pdev;

	pdev = (mmc_info_t*)priv_data;
	
	if(count <= 0)
		return 0;

	// Use DMA safe buffer as relay
	memcpy(k_buffer, buf, count);
	#ifdef CONFIG_BFIN
	blackfin_dcache_flush_range((unsigned long)k_buffer,(unsigned long)(k_buffer+count));
	#endif

	spi_message_init(&m);
	memset(&t, 0, (sizeof t));

	t.tx_buf = k_buffer;
	t.len = count;
	t.speed_hz = pdev->spi_speed_hz;

	spi_message_add_tail(&t, &m);

	// write on dummy device
	if(pdev->msd.force_cs_high) {
		spi_sync(dummy_spi, &m);
	} else {
		spi_sync(pdev->spi_dev, &m);
	}

	if(m.status) {
		DPRINTK("status: %d\n", m.status);
		return m.status;
	}

	return count;
}
static int read_func(unsigned char *buf, unsigned int count, void* priv_data) 
{
	struct spi_transfer t;
	struct spi_message m;
	mmc_info_t *pdev;

	pdev = (mmc_info_t*)priv_data;
	
	if(count <= 0)
		return 0;

	#ifdef CONFIG_BFIN
	/* Invalidate allocated memory in Data Cache */
	blackfin_dcache_invalidate_range((unsigned long)k_buffer,(unsigned long)(k_buffer+count));
	#endif

	spi_message_init(&m);
	memset(&t, 0, (sizeof t));

	t.rx_buf = k_buffer;
	t.len = count;
	t.speed_hz = pdev->spi_speed_hz;

	spi_message_add_tail(&t, &m);
	spi_sync(pdev->spi_dev, &m);

	if(m.status) {
		DPRINTK("status: %d\n", m.status);
		return m.status;
	}
	
	//copy from DMA safe relay buffer
	memcpy(buf, k_buffer, count);
	return count;
}
		
static unsigned long stamp_msec;
static void reset_time_func(unsigned long msec)
{
	// set to sometime in the future
	stamp_msec = jiffies + msec * HZ / 1000;	
}
static int elapsed_time_func(void)
{
	/* returns true when NOW is equal or beyond stamp_msec */
	return time_after(jiffies, stamp_msec);
}

/**********************************************************************\
*
* Block device operations and helpers
*
\**********************************************************************/
static int spi_mmc_card_init(mmc_info_t* pdev) 
{	
	u_long sclk;

	// TODO: get system clock frequency, preferrably platform independend, how?
	// TODO: Adjust maximum speed to card maximum(said to be found in CSD reg.) and sclk.
	
	// set SPI to init rate
	#ifdef CONFIG_BFIN
	sclk = spi_get_sclk();
	pdev->spi_speed_hz = sclk/(2*SPI_CLOCK_INIT_HZ)+1;
	#else
	pdev->spi_speed_hz = SPI_CLOCK_INIT_HZ;
	#endif

	// MMC card init
        if( mmc_spi_init_card(&(pdev->msd)) ) {
		// default to zero-size card
		pdev->nsectors = 0;
		pdev->hardsect_size = KERNEL_SECTOR_SIZE;
		return 1;
	}

	// reset to max speed if successful init
	#ifdef CONFIG_BFIN
	pdev->spi_speed_hz = sclk/(2*SPI_CLOCK_MAX_HZ)+1;
	#else
	pdev->spi_speed_hz = SPI_CLOCK_MAX_HZ;
	#endif

	return 0;
}

static int spi_mmc_init_regs(mmc_info_t* pdev)
{
	//could incorporate some kind of sanity check of more parameters

	memset(&(pdev->card.csd), 0, sizeof(pdev->card.csd));
	memset(&(pdev->card.cid), 0, sizeof(pdev->card.cid));
	
	pdev->card.csd.mmca_vsn = pdev->msd.csd.mmca_vsn;
	pdev->card.csd.cmdclass = pdev->msd.csd.cmdclass;
	pdev->card.csd.tacc_clks = pdev->msd.csd.tacc_clks;
	pdev->card.csd.tacc_ns = pdev->msd.csd.tacc_ns;
	pdev->card.csd.max_dtr = pdev->msd.csd.max_dtr;
	pdev->card.csd.read_blkbits = pdev->msd.csd.read_blkbits;
	pdev->card.csd.capacity = pdev->msd.csd.capacity;

	pdev->card.cid.manfid = pdev->msd.cid.manfid;
	memcpy(pdev->card.cid.prod_name, pdev->msd.cid.prod_name, 7);
	pdev->card.cid.serial = pdev->msd.cid.serial;
	pdev->card.cid.oemid = pdev->msd.cid.oemid;
	pdev->card.cid.year = pdev->msd.cid.year;
	pdev->card.cid.hwrev = pdev->msd.cid.hwrev;
	pdev->card.cid.fwrev = pdev->msd.cid.fwrev;
	pdev->card.cid.month = pdev->msd.cid.month;	
	
	// only return path for now
	return 0;
}
/*
 * Function:    spi_mmc_dev_init()
 *
 * Purpose:	Initializes the device
 *
 * Arguments:   pdev
 *		
 * Lock status: Assumed that lock IS held upon entry.
 *
 * Returns	-NODEV on init fail, 0 for success
 *
 * Notes:
 *
 */
static int spi_mmc_dev_init(mmc_info_t* pdev)
{
	struct block_device *bdev;
	static unsigned int last_read_serial=0;
	unsigned int cap;
	
	// Low level init of card
	if(spi_mmc_card_init(pdev)) {
		return -ENODEV;
	}

	// Ask for CSD and CID data
	if(mmc_spi_get_card(&pdev->msd)) {
		printk(KERN_ERR "Could not read this MMC/SD card CSD/CID registers.\n");
		return -ENODEV;
	}
	
	// copy mmc_spi CSD CID data to linux version of CSD/CID
	if(spi_mmc_init_regs(pdev)) {
		printk(KERN_ERR "Unsupported CSD/CID registry entry.\n");
		return -ENODEV;
	}
	
	pdev->hardsect_size = (1 << pdev->card.csd.read_blkbits);
	// set block device size parameters from card parameters(2^READ_BLOCK_LEN)
	if(pdev->hardsect_size < KERNEL_SECTOR_SIZE) {
		printk(KERN_ERR "MMC/SD has invalid sector size.\n");
		return -ENODEV;
	}	
	pdev->nsectors = pdev->card.csd.capacity;
	
	// Show some device information to log if _NEW_ MMC was found
	if(pdev->card.cid.serial != last_read_serial) {
		cap = pdev->card.csd.capacity * (1 << pdev->card.csd.read_blkbits);
		printk(KERN_INFO "New MMC/SD card found: %d MB | CS channel on PF%d\n",cap/(1024*1024), CONFIG_SPI_MMC_CS_CHAN);
		// force read of partition table
		bdev = bdget_disk(pdev->gd, 0);
		bdev->bd_invalidated = 1;
		// clear perf_info struct and error information
		memset(&pdev->pi, 0, sizeof(struct perf_info));
		memset(pdev->msd.error_log, 0, sizeof(pdev->msd.error_log));
		memset(pdev->msd.status_log, 0, sizeof(pdev->msd.status_log));
		pdev->msd.errors = 0;
		
		// assume that it works
		pdev->pi.mbw_works=1;
	}

	// Keep what number we got this time
	last_read_serial = pdev->card.cid.serial;

	return 0;	
}

#ifdef CONFIG_BFIN
static inline
void spi_mmc_delayed_revalidate(mmc_info_t *pdev, int timeout)
{
	/* guess card is removed */
	if (pdev->card_in_bay || timeout == 0) {
		schedule_work(&card_work);
	} else {
		int j = jiffies + msecs_to_jiffies(timeout);
		pdev->card_in_bay = 0;
		mod_timer(&pdev->revalidate_timer, j);
	}
}

static
void spi_mmc_revalidate_timeout(mmc_info_t* pdev)
{
	schedule_work(&card_work);
}

/*
 * Function:    spi_mmc_dev_init()
 *
 * Purpose:	Interrupt handler triggerd by card_detect signal from MMC/SD card
 *
 * Arguments:   pdev
 *		
 * Lock status: Assumed that lock IS held upon entry.
 *
 * Returns	-NODEV on init fail, 0 for success
 *
 * Notes:	Trigger on both flanks, and schedules revalidation allways
 *
 */

irqreturn_t spi_mmc_detect_irq_handler(int irq, void *dev_id, struct pt_regs *regs)
{
	mmc_info_t* pdev;
	pdev = (mmc_info_t*)dev_id;

	spi_mmc_delayed_revalidate(pdev, CARD_DETECT_INTERVAL);
    
	// return
	return IRQ_HANDLED;
}
#endif

// Worker for doing the revalidation work when it is considered
// a too lengthy or impossible process since it will do some sleeping etc.
static void spi_mmc_media_worker(void* arg)
{
	mmc_info_t* pdev;

	pdev = (mmc_info_t*)arg;

	spi_mmc_revalidate(pdev->gd);
}

static int spi_mmc_revalidate(struct gendisk *gd)
{
	mmc_info_t* pdev = gd->private_data;

	down_interruptible(&card_sema);
	
	if(spi_mmc_dev_init(pdev)) {
		// No card
		pdev->card_in_bay = 0;
		pdev->nsectors = 0;
	} else {
		// (re)-configure sector size and capacity on current card
		blk_queue_hardsect_size(pdev->gd->queue, pdev->hardsect_size);
		pdev->card_in_bay = 1;
	}
	set_capacity(pdev->gd, pdev->nsectors * (pdev->hardsect_size / KERNEL_SECTOR_SIZE));
	
	up(&card_sema);

	return 0;
}

static int spi_mmc_media_changed(struct gendisk *gd)
{
	DPRINTK("\n");
	/*
	if(spi_mmc_media_check((mmc_info_t*)(gd->private_data)) == 1) {
		return 1;
	}
	*/
	return 0;
}

static int spi_mmc_ioctl(struct inode *inode, struct file *filp, unsigned int cmd,
	      unsigned long arg)
{
	struct block_device *bdev = inode->i_bdev;
	struct hd_geometry geo;

	DPRINTK("\n");

	if (cmd == HDIO_GETGEO) {

		memset(&geo, 0, sizeof(struct hd_geometry));

		geo.cylinders	= get_capacity(bdev->bd_disk) / (GEO_HEADS * GEO_SECTORS);
		geo.heads	= GEO_HEADS; 
		geo.sectors	= GEO_SECTORS;
		geo.start	= 4; //get_start_sect(bdev);

		return copy_to_user((void __user *)arg, &geo, sizeof(geo))
			? -EFAULT : 0;
	}

	return -ENOTTY;
}

static int spi_mmc_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
	DPRINTK("\n");

	geo->cylinders	= get_capacity(bdev->bd_disk) / (GEO_HEADS * GEO_SECTORS);

	geo->heads	= GEO_HEADS;
	geo->sectors	= GEO_SECTORS;
	geo->start	= get_start_sect(bdev);
	
	return 0;
}


static int spi_mmc_open(struct inode *inode, struct file *filp)
{
	mmc_info_t* pdev;
	int rval = 0;

	pdev  = (mmc_info_t*)(inode->i_bdev->bd_disk->private_data);
	
	//down(&open_lock);
	pdev->users++;
	DPRINTK("\n");

	// allways do full init and revalidation if not on hotplug platform
#ifndef CONFIG_SPI_MMC_CARD_DETECT
	spi_mmc_revalidate(pdev->gd);
#endif
	if(!pdev->card_in_bay) {
		// no card found...
		rval = -ENODEV;
		pdev->users--;
	}
	//up(&open_lock);

	return rval;
}

static int spi_mmc_release(struct inode *inode, struct file *filp)
{	
	mmc_info_t* pdev;
	pdev  = (mmc_info_t*)(inode->i_bdev->bd_disk->private_data);
	
	// NOTE: Not sure whether this open_lock is needed anymore
	//down(&open_lock);
	DPRINTK("\n");
	if(pdev->users > 0) {
		pdev->users--;
	}
	//up(&open_lock);
	return 0;
}


static struct block_device_operations spi_mmc_ops = {
	.owner = THIS_MODULE,
	.open = spi_mmc_open,
	.release = spi_mmc_release,
	.media_changed = spi_mmc_media_changed,
	.revalidate_disk = spi_mmc_revalidate,
	.ioctl = spi_mmc_ioctl,
	.getgeo = spi_mmc_getgeo,
};

/**********************************************************************\
*
* /proc entry and module init and exit.
*
\**********************************************************************/
int spi_mmc_read_proc(char *buf, char **start, off_t offset, int count, int *eof, void *data)
{
	mmc_info_t *pdev = Devices;
	int len = 0;
	int idx = 0;
	unsigned int spi_speed_khz=0;
	unsigned int sclk=0;
	
	#ifdef CONFIG_BFIN
	sclk = spi_get_sclk();
	spi_speed_khz = (unsigned int)(sclk/(2 * pdev->spi_speed_hz))/1000;
	#else
	spi_speed_khz = pdev->spi_speed_hz/1000;
	#endif
	
	// add to len if iterative..
	len += sprintf(buf+len, "Driver build date: %s\n", __DATE__);
	len += sprintf(buf+len, "Driver author: %s\n", __DRIVER_AUTHOR);
	len += sprintf(buf+len, "SPI CLK: %d KHz\n", spi_speed_khz);
	len += sprintf(buf+len, "SPI CS : %d\n", CONFIG_SPI_MMC_CS_CHAN);

	len += sprintf(buf+len, "Error/Status log[0xNEW, 0x0000, 0xOLDEST]. Total: %d\n", pdev->msd.errors);
	len += sprintf(buf+len, "E: ");
	for(idx=0; idx < pdev->msd.log_len; idx++) {
		len += sprintf(buf+len, " 0x%04x", pdev->msd.error_log[idx]);
	}
	len += sprintf(buf+len, "\nS: ");
	for(idx=0; idx < pdev->msd.log_len; idx++) {
		len += sprintf(buf+len, " 0x%04x", pdev->msd.status_log[idx]);
	}

	len += sprintf(buf+len, "\n");
	if(!pdev->card_in_bay) {
		len += sprintf(buf+len, "No MMC/SD card found.\n");
		goto out;
	}

	if(pdev->msd.sd) {
		len += sprintf(buf+len, "SD card :\n");
	} else {
		len += sprintf(buf+len, "MMC :\n");
	}
	len += sprintf(buf+len, "\t Capacity: %d B\n", pdev->card.csd.capacity * (1 << pdev->card.csd.read_blkbits));
	len += sprintf(buf+len, "\t Name: %s \n",  pdev->card.cid.prod_name);
	len += sprintf(buf+len, "\t Rev: %d.%d \n", pdev-> card.cid.hwrev, pdev->card.cid.fwrev);
	len += sprintf(buf+len, "\t Date: %d/%d \n", pdev->card.cid.year, pdev->card.cid.month);
	len += sprintf(buf+len, "\t Serial: 0x%x (%u)\n",  pdev->card.cid.serial, pdev->card.cid.serial);
	len += sprintf(buf+len, "\t CSD ver.: %d\n", pdev->card.csd.mmca_vsn);
	len += sprintf(buf+len, "\t CCC supported: %x\n", pdev->card.csd.cmdclass);
	if(pdev->pi.mbw_works) {
		len += sprintf(buf+len, "\t Mult. block writes works: YES\n");
	} else {
		len += sprintf(buf+len, "\t Mult. block writes works: NO\n");
	}



	len += sprintf(buf+len, "last block: \t %u\n", pdev->pi.last_block);
	len += sprintf(buf+len, "users: \t %d\n", pdev->users);

	len += sprintf(buf+len, "Performance for last 100 transfers\n");
	len += sprintf(buf+len, "\t Mean read throughput:\t %d kB/s\n", pdev->pi.mean_read_tp);
	len += sprintf(buf+len, "\t Mean write throughput:\t %d kB/s\n", pdev->pi.mean_write_tp);
	

	*eof=1;

	out:
	return len;
}

// Platform dependent lowlevel init for GPIO pin to use for card detection
#if defined(CONFIG_SPI_MMC_CARD_DETECT) && defined(CONFIG_BFIN)
static void spi_mmc_bfin_cd_setup(mmc_info_t *pdev) 
{
	// request interrupt handler for card detect signal
	if (request_irq(CARD_DETECT_IRQ, spi_mmc_detect_irq_handler, 
		IRQF_TRIGGER_RISING|IRQF_TRIGGER_FALLING|IRQF_DISABLED, SPI_MMC_DEVNAME, pdev)) {
		printk(KERN_WARNING "spi_mmc: IRQ %d is not free, No card detection.\n", IRQ_PROG_INTA);
	}
}
#endif

static void spi_mmc_clean(void)
{
	mmc_info_t* pdev;
	pdev = Devices;
	
#if defined(CONFIG_BFIN) && defined(CONFIG_SPI_MMC_CARD_DETECT)
	del_timer(&pdev->revalidate_timer);
	free_irq(CARD_DETECT_IRQ, pdev);
#endif
	// releasae disks and deallocate device array
	if (pdev->gd) {
		del_gendisk(pdev->gd);
		put_disk(pdev->gd);
	}
	if (pdev->gd->queue) {
		blk_put_queue(pdev->gd->queue);
		// if other kind of request are used, consider how to clean
	}
	
	kfree(Devices);
	remove_proc_entry(SPI_MMC_DEVNAME, NULL /* parent dir */);
	unregister_blkdev(MAJOR_NUMBER, SPI_MMC_DEVNAME);
}

static int spi_mmc_remove(struct spi_device *spi) {
	spi_mmc_clean();
	return 0;
}

static int spi_mmc_dummy_probe(struct spi_device *spi) {
	// not sure if spi_mmc_probe has been done, just assign to
	// a file-scope accessible variable
	dummy_spi = spi;

	return 0;
}
static int spi_mmc_dummy_remove(struct spi_device *spi) {
	return 0;
}

static int __devinit spi_mmc_probe(struct spi_device *spi)
{
	mmc_info_t *pdev;
	
	/*
	 * Get registered.
	 */
	if (register_blkdev(MAJOR_NUMBER, SPI_MMC_DEVNAME)) {
		printk(KERN_WARNING "spi_mmc: unable to get major number\n");
		return -EBUSY;
	} else {
		DPRINTK("Major number %d was ok\n", MAJOR_NUMBER);
	}
	
	// allocate DMA safe buffer for SPI transactions
	k_buffer = kmalloc(KERNEL_SECTOR_SIZE, GFP_KERNEL);

	// generate private custom descriptor
	pdev = kmalloc(sizeof(mmc_info_t), GFP_KERNEL);
	// save pointer for module exit cleanup
	Devices = pdev;
	
	if(!pdev) {
		printk(KERN_WARNING "spi_mmc: could not allocate device structure.\n");
		goto out;
	}
	
	// register proc read function
	create_proc_read_entry(SPI_MMC_DEVNAME, 0 /*def mode */, NULL /* parent dir */, spi_mmc_read_proc, NULL /* client data */);

	/* reset the main descriptor */
	memset(pdev, 0, sizeof(mmc_info_t));
	
	// set mmc_spi_mode callbacks
	pdev->msd.read = read_func;
	pdev->msd.write = write_func;
	pdev->msd.reset_time = reset_time_func;
	pdev->msd.elapsed_time = elapsed_time_func;
	pdev->msd.priv_data = pdev;

	// Set the assigned spi_device to our self
	pdev->spi_dev = spi;

#if defined(CONFIG_SPI_MMC_CARD_DETECT)
	init_timer(&pdev->revalidate_timer);
	pdev->revalidate_timer.data = (unsigned long) pdev;
	pdev->revalidate_timer.function = (void *)spi_mmc_revalidate_timeout;
#endif
	
	spin_lock_init(&pdev->queue_lock);
	spin_lock_init(&pdev->dev_lock);

	pdev->gd = alloc_disk(MINORS);

	if (!pdev->gd) {
		printk(KERN_NOTICE "alloc_disk failure\n");
		goto out;
	}
	/*
	Default values:
	MAX_PHYS_SEGMENTS 128
	MAX_HW_SEGMENTS 128
	MAX_SECTORS 255
	MAX_SEGMENT_SIZE 65536
	*/

	pdev->max_phys_segments = 16;
	pdev->max_hw_segments = 16;
	pdev->max_sectors = 32;
	pdev->max_segment_size = 8192;
	
	// initialize the gendisk descriptor
	pdev->gd->private_data = pdev;
	pdev->gd->major = MAJOR_NUMBER;
	pdev->gd->first_minor = 0;
	pdev->gd->minors = MINORS;
	snprintf(pdev->gd->disk_name, 32, SPI_MMC_DEVNAME);
	//pdev->gd->flags |= GENHD_FL_REMOVABLE;	// not set even though it is removeable
						//   as discussed in drivers/mmc/mmc_block.c
	pdev->gd->fops = &spi_mmc_ops;
	
	// Allocation of request queue, spi_mmc_make_request is our custom make_request function
	switch (request_mode) {
		case RM_NOQUEUE:
			pdev->gd->queue = blk_alloc_queue(GFP_KERNEL);
			if (pdev->gd->queue == NULL)
				goto out;
			blk_queue_make_request(pdev->gd->queue, spi_mmc_make_request);
			break;
		case RM_FULL:
			pdev->gd->queue = blk_init_queue(spi_mmc_strategy, &pdev->queue_lock);
			if (pdev->gd->queue == NULL)
				goto out;		
			break;
	}
	pdev->gd->queue->queuedata = pdev;
	
	blk_queue_max_phys_segments(pdev->gd->queue, pdev->max_phys_segments);
	blk_queue_max_hw_segments(pdev->gd->queue, pdev->max_hw_segments);
	blk_queue_max_sectors(pdev->gd->queue, pdev->max_sectors);
	blk_queue_max_segment_size(pdev->gd->queue, pdev->max_segment_size);
	

	// configure work to check for card in bay
	PREPARE_WORK(&card_work, spi_mmc_media_worker, (void*)pdev);
	PREPARE_WORK(&transfer_work, spi_mmc_transfer_worker, (void*)pdev);


	// NOTE: add init for card detection pin here
	#if defined(CONFIG_SPI_MMC_CARD_DETECT) && defined(CONFIG_BFIN)
	spi_mmc_bfin_cd_setup(pdev);
	#endif
	
	// schedule to check for media
	schedule_work(&card_work);
	
	// add this disk to system
	add_disk(pdev->gd);


	return 0;
	
	out:
	DPRINTK("spi_mmc: probe failed!\n");
	//up(&pdev->sem);
	spi_mmc_clean();
	return -ENODEV;	
}

static struct spi_driver spi_mmc_driver = {
	.driver = {
		.name	= SPI_MMC_DEVNAME,
		.bus	= &spi_bus_type,
		.owner	= THIS_MODULE,
	},
	.probe	= spi_mmc_probe,
	.remove	= __devexit_p(spi_mmc_remove),
};

static struct spi_driver spi_mmc_dummy_driver = {
	.driver = {
		.name	= SPI_MMC_DUMMY_DEVNAME,
		.bus	= &spi_bus_type,
		.owner	= THIS_MODULE,
	},
	.probe	= spi_mmc_dummy_probe,
	.remove	= spi_mmc_dummy_remove,
};

static int spi_mmc_init(void)
{
	spi_register_driver(&spi_mmc_dummy_driver);
	return spi_register_driver(&spi_mmc_driver);
}


static void spi_mmc_exit(void)
{
	spi_unregister_driver(&spi_mmc_dummy_driver);
	spi_unregister_driver(&spi_mmc_driver);
}

module_init(spi_mmc_init);
module_exit(spi_mmc_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MMC/SD card driver over SPI block device driver");

