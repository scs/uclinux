/*
 * File:         sound/blackfin/ac97_sport.c
 * Based on:
 * Author:       Luuk van Dijk, Bas Vermeulen
 *
 * Created:      Sat Dec  6 21:40:06 CET 2003
 * Description:  low level driver for ac97 connected to sportX/dmaY on blackfin 53x
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright (C) 2003 Luuk van Dijk, Bas Vermeulen BuyWays B.V.
 *               Copyright 2003-2006 Analog Devices Inc.
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


/* theory of operation: we have a rx and a tx buffer
 * which is filled/emptied in dma autobuffer mode
 * we generate an interrupt each 'fragment'
 * commands are copied to/from the cmd fifo to the
 * cmd channel in the next fragment
 * audio data is copied to/from the buffer by the user in an async way
 * this is no problem if we read/write sufficiently large fragments at a time
 * the copy to/from user routine will refuse to copy data if there is not enough
 * room.  optimum and max fragment size should be about half a buffer.
 */



/*
 * note: currently we only handle stereo reception and transmission
 * we also assume that we run in variable frame rate, i.e.: frames
 * come with the sample frequency, and each received/transmitted frame
 * contains valid pcm audio data!!
 */


#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/config.h>
#include <asm/blackfin.h>
#include <asm/dma.h>
#include <linux/dma-mapping.h>
#include "ac97_sport.h"

#include "bf53x_structs.h"

#define bzero(buf, size)	memset(buf, 0, size)

//#define  AC97_SPORT_DEBUG
#undef  AC97_TALKTHROUGH_DIRECT

/*
 * frame communicated over the ac97 sport link
 */
struct ac97_frame
{
	__u16 ac97_tag;   // slot 0
#define TAG_VALID 0x8000
#define TAG_CMD   0x6000
#define TAG_PCM_LEFT   0x1000
#define TAG_PCM_RIGHT  0x0800
#define TAG_PCM  (TAG_PCM_LEFT|TAG_PCM_RIGHT)
	__u16 ac97_addr;  // slot 1
	__u16 ac97_data;  // slot 2
	__u32 ac97_pcm;   // slot 3 and 4: left and right pcm data
	__u16 stuff[11];  // pad to 16 words
} __attribute__ ((packed));


struct ac97_sport_dev_t
{
	size_t bufsize;     // size of r/tx buffer allocated in units of ac97frame!
	size_t fragsize;    // size of r/tx fragments in units of ac97frame!
	int    fragcount;   // bufsize/fragsize

	struct ac97_frame* txbuf;
	struct ac97_frame* rxbuf;

	struct dma_descriptor_block* tx_desc;
	struct dma_descriptor_block* rx_desc;

	int tx_currfrag;        // fragment currently being handled by DMA
	int rx_currfrag;

	int tx_lastfrag;        // fragment last handled by irq
	int rx_lastfrag;

	int *cmd_count;         // number of commands queued in current 'safe' buffer

	size_t rx_tail;         // index of last read pcm sample
	size_t tx_head;         // index of last written pcm sample

	int codec_ready;        // we received frames with the 'valid' bit set
	int codec_initialized;  // we sent the ac97 initialization

	wait_queue_head_t audio_in_wait;
	wait_queue_head_t audio_out_wait;

	__u16 register_cache[128];     // ac97 register cache
	__u16 register_dirty[128/16];  // flag: clear when read-back after write happened
};


#define reg_set_clean(reg)  (dev.register_dirty[(reg) >> 4] &= ~(1 << ((reg) & 0x000f)))
#define reg_set_dirty(reg)    (dev.register_dirty[(reg) >> 4] |=  (1 << ((reg) & 0x000f)))
#define reg_is_dirty(reg)     (dev.register_dirty[(reg) >> 4] &   (1 << ((reg) & 0x000f)))
#define reg_any_dirty()       (dev.register_dirty[0] || dev.register_dirty[1] \
                            || dev.register_dirty[2] || dev.register_dirty[3] \
                            || dev.register_dirty[4] || dev.register_dirty[5] \
                            || dev.register_dirty[6] || dev.register_dirty[7] )


/*
 * one global device struct
 * get rid of all the dev arguments and let the linker do the indirection work
 */
struct ac97_sport_dev_t dev;

dma_addr_t addr;

/*
 * setup sport and dma for communication with ac97 device
 */

static void sport_init(void)
{

	SPORT0->MTCS0 = SPORT0->MRCS0 = 0x0000ffff;  /* Enable only first 16 transmit/receive channels */
	SPORT0->MTCS1 = SPORT0->MRCS1 = 0x00000000;
	SPORT0->MTCS2 = SPORT0->MRCS2 = 0x00000000;
	SPORT0->MTCS3 = SPORT0->MRCS3 = 0x00000000;

	/* frame size 16 words; enable Multichannel mode & dma packing,
	 * frame delay = 1 bit */
	SPORT0->MCMC1 = 0x1000; /* window size = (1+1) * 8 words */
	SPORT0->MCMC2 = 0x1000 | MCMEN; /* frame delay = 1 bit, etc */
	/* generate sync every 16th word */
	SPORT0->RFSDIV = SPORT0->TFSDIV = (16*16) - 1;
	/* rx config: IRFS, SLEN=1111, tx config: slen=1111 */
	SPORT0->RCR1 = IRFS;
	SPORT0->TCR1 = ITFS;
	SPORT0->RCR2 = SPORT0->TCR2 = 0x000f; /* wordlen = 0xf + 1 */
}

// bufsize and fragsize in units of ac97 frames!

#define WORDS_PER_FRAME (sizeof(struct ac97_frame)/sizeof(__u16))
#define BYTES_PER_FRAME (sizeof(struct ac97_frame))
#define LOG_BYTES_PER_FRAME 5  /* this better be true: 2 << LOG_BYTES_PER_FRAME == BYTES_PER_FRAME */



static void dma_init_xmit(void* data, size_t bufsize, size_t fragsize)
{
	int i, fragcount = bufsize/fragsize;  /* this better be an integer */

#if L1_DATA_A_LENGTH != 0
	dev.tx_desc = (struct dma_descriptor_block*)l1_data_A_sram_alloc(sizeof(struct dma_descriptor_block) * fragcount);
#else
	dev.tx_desc = dma_alloc_coherent(NULL,sizeof(struct dma_descriptor_block) * fragcount, &addr, 0);
#endif
//	dev.tx_desc = kmalloc(sizeof(struct dma_descriptor_block) * fragcount, GFP_KERNEL);
	for (i = 0; i < fragcount; i++) {
		dev.tx_desc[i].next = (unsigned long)&dev.tx_desc[i+1];
		dev.tx_desc[i].start_addr = (unsigned long)data +
			(i * fragsize * BYTES_PER_FRAME);
		dev.tx_desc[i].x_count = WORDS_PER_FRAME;
		dev.tx_desc[i].x_modify = sizeof(__u16);
		dev.tx_desc[i].y_count = fragsize;
		dev.tx_desc[i].y_modify = sizeof(__u16);
		/* Large descriptor mode, generate interrupt after each
		 * outer loop (after each fragment) */
		dev.tx_desc[i].dma_config = (DMAFLOW_LARGE |
			NDSIZE_9 | DI_EN |
			DMA2D | WDSIZE_16 | DMAEN);
	}
	/* Close the circle */
	dev.tx_desc[fragcount - 1].next = (unsigned long)dev.tx_desc;

	DMA4->NEXT_DESC_PTR = dev.tx_desc;
	DMA4->CONFIG = (unsigned long)dev.tx_desc->dma_config;
}


static void dma_init_recv(void* data, size_t bufsize, size_t fragsize)
{
	int i, fragcount = bufsize/fragsize;  /* this better be an integer */

#if L1_DATA_A_LENGTH != 0
	dev.rx_desc = (struct dma_descriptor_block*)l1_data_A_sram_alloc(sizeof(struct dma_descriptor_block) * fragcount);
#else
	dev.rx_desc = dma_alloc_coherent(NULL,sizeof(struct dma_descriptor_block) * fragcount, &addr, 0);
#endif
//	dev.rx_desc = kmalloc(sizeof(struct dma_descriptor_block) * fragcount, GFP_KERNEL);
	for (i = 0; i < fragcount; i++) {
		dev.rx_desc[i].next = (unsigned long)&dev.rx_desc[i+1];
		dev.rx_desc[i].start_addr = (unsigned long)data +
			(i * fragsize * BYTES_PER_FRAME);
		dev.rx_desc[i].x_count = WORDS_PER_FRAME;
		dev.rx_desc[i].x_modify = sizeof(__u16);
		dev.rx_desc[i].y_count = fragsize;
		dev.rx_desc[i].y_modify = sizeof(__u16);
		/* Large descriptor mode, generate interrupt after each
		 * outer loop (after each fragment) */
		dev.rx_desc[i].dma_config = (DMAFLOW_LARGE |
			NDSIZE_9 | DI_EN |
			DMA2D | WDSIZE_16 | WNR | DMAEN);
	}
	/* Close the circle */
	dev.rx_desc[fragcount - 1].next = (unsigned long)dev.rx_desc;

	DMA3->NEXT_DESC_PTR = dev.rx_desc;
	DMA3->CONFIG = dev.rx_desc->dma_config;
}


// 1 = enable, -1 = disable, other = don't change
static void sport_enable(int tx, int rx)
{
	if (tx ==  1) SPORT0->TCR1 |=  TSPEN;
	if (tx == -1) SPORT0->TCR1 &= ~TSPEN;
	if (rx ==  1) SPORT0->RCR1 |=  RSPEN;
	if (rx == -1) SPORT0->RCR1 &= ~RSPEN;
	return;
}

int ac97_sport_open(size_t bufsize, size_t fragsize)
{
	int i;

	bzero(&dev,sizeof(dev));

	/* bufsize must be a multiple of fragsize */
	if (bufsize % fragsize)
		return -EINVAL;

	/* See dma_init_XX */
	if ((fragsize) >= 0x10000)
		return -EINVAL;

	dev.bufsize   = bufsize;
	dev.fragsize  = fragsize;
	dev.fragcount = bufsize/fragsize;

	dev.rxbuf = dma_alloc_coherent(NULL,bufsize * sizeof(struct ac97_frame), &addr, 0);
	dev.txbuf = dma_alloc_coherent(NULL,bufsize * sizeof(struct ac97_frame), &addr, 0);
	dev.cmd_count = dma_alloc_coherent(NULL,dev.fragcount * sizeof(int), &addr, 0);

	dev.tx_desc = NULL;
	dev.rx_desc = NULL;

	if (!dev.rxbuf || !dev.txbuf || !dev.cmd_count) {
	  ac97_sport_close();
	  return -ENOMEM;
	}

	bzero(dev.rxbuf, bufsize * sizeof(struct ac97_frame));
	bzero(dev.txbuf, bufsize * sizeof(struct ac97_frame));
	for (i = 0; i < bufsize; i++)
		dev.txbuf[i].ac97_tag = TAG_VALID | TAG_PCM;
	bzero(dev.cmd_count, dev.fragcount * sizeof(int));

	init_waitqueue_head(&dev.audio_in_wait);
	init_waitqueue_head(&dev.audio_out_wait);


	/* mark the register cache all clean, even if they are dirty
	   we'd rather mark everything dirty,  but chances are we won't
	   get an answer for every register query.
	   TODO: figure out which ones to mark dirty
	 */
	for (i=0; i<128; i++)
		reg_set_clean(i);

	/* First thing to send is 'serial mode 16x16' command
	 * Watch out: This may get sent in 20 bits mode,
	 * in which case the first nibble of data is 'eaten'
	 * by the addr. (Tag is always 16 bit)
	 *
	 * Just put the command in the very first frame, as
	 * we can't use enqueue_cmd when dma is not enabled.
	 */
	dev.txbuf[0].ac97_tag |= TAG_CMD;
	dev.txbuf[0].ac97_addr = 0x7400;
	dev.txbuf[0].ac97_data = 0x9900;

	sport_init();

	dma_init_recv(dev.rxbuf, bufsize, fragsize);
	dma_init_xmit(dev.txbuf, bufsize, fragsize);

	return 0;
}



void ac97_sport_close(void)
{
	sport_enable(-1,-1);

#if L1_DATA_A_LENGTH != 0
	if (dev.tx_desc) l1_data_A_sram_free(dev.tx_desc);
	if (dev.rx_desc) l1_data_A_sram_free(dev.rx_desc);
#else
	if (dev.tx_desc) dma_free_coherent(NULL,sizeof(struct dma_descriptor_block) * dev.fragcount, dev.tx_desc, 0);
	if (dev.rx_desc) dma_free_coherent(NULL, sizeof(struct dma_descriptor_block) * dev.fragcount, dev.rx_desc, 0);
#endif

	if (dev.rxbuf) dma_free_coherent(NULL, dev.bufsize * sizeof(struct ac97_frame), dev.rxbuf, 0);
	if (dev.txbuf) dma_free_coherent(NULL, dev.bufsize * sizeof(struct ac97_frame), dev.txbuf, 0);
	if (dev.cmd_count) dma_free_coherent(NULL, dev.fragcount * sizeof(int), dev.cmd_count, 0); 

	bzero(&dev, sizeof(dev));

	return;
}



void ac97_sport_start(void)
{
	sport_enable(1,1);
}
void ac97_sport_stop(void)
{
	sport_enable(-1,-1);
}




// short circuit rx and tx audio, and set mixer for talkthrough mode

void ac97_sport_set_talkthrough_mode(void)
{
  /* TODO */
}

static int set_current_tx_fragment(void)
{
	return dev.tx_currfrag = ((u32)(DMA4->CURR_ADDR) - (unsigned long)dev.txbuf) / (sizeof(struct ac97_frame) * dev.fragsize);
}

static int set_current_rx_fragment(void)
{
	return dev.tx_currfrag = ((u32)(DMA3->CURR_ADDR) - (unsigned long)dev.rxbuf) / (sizeof(struct ac97_frame) * dev.fragsize);
}

static void incfrag(int *frg)
{
	++(*frg);
	if (*frg == dev.fragcount)
		*frg = 0;
}

static void decfrag(int *frg)
{
	if (*frg == 0)
		*frg = dev.fragcount;
	--(*frg);
}


static void enqueue_cmd(__u16 addr, __u16 data)
{
	int nextfrag = set_current_tx_fragment();
	struct ac97_frame *nextwrite;

	incfrag(&nextfrag);
	incfrag(&nextfrag);

	nextwrite = dev.txbuf + nextfrag * dev.fragsize;
	nextwrite[dev.cmd_count[nextfrag]].ac97_addr = addr;
	nextwrite[dev.cmd_count[nextfrag]].ac97_data = data;
	nextwrite[dev.cmd_count[nextfrag]].ac97_tag  |= TAG_CMD;
	++dev.cmd_count[nextfrag];
#ifdef AC97_SPORT_DEBUG
	printk(KERN_INFO "ac97_sport: Inserting %02x/%04x into fragment %d\n",
			addr >> 8, data, nextfrag);
#endif
}

static void init_ac97(void)
{
	dev.codec_initialized = 1;

	/* Read all the registers.
	 * We use this to only check the receive buffer when necessary
	 */
	//for (i=0; i<128; i+=2)
	//	enqueue_cmd((i<<8)|0x8000, 0);

	/* Initialize the AC97 */
	ac97_sport_set_register(0x2a, 0x0001);  // set variable bitrate
	ac97_sport_set_register(0x02, 0x0000);  // AC97_MASTER_VOLUME  unmute
	ac97_sport_set_register(0x18, 0x0000);  // AC97_PCM_OUT_VOLUME unmute

	ac97_sport_set_register(0x04, 0x0000);  // AC97_HP_OUT_VOLUME unmute

	ac97_sport_set_register(0x1a, 0x0404);  // AC97_RECORD_SELECT  line-in
	ac97_sport_set_register(0x1c, 0x0000);  // AC97_RECORD_GAIN,   unmute
}






/*
 * interrupt handlers: get called every fragment
 * when a rx or tx dma inner loop is done
 * sport{0,1}_{t,r}x is by default assigned to periph int 9/ivg9/core int 2
 * this corresponds to dma1/2/3/4
 * call this from the interrupt handler scheduled for these dma
 */

/*
 * on rx: check if we got any commands
 * return 0: success
 *        -EINPROGRESS: dma not asserted
 */

int ac97_sport_handle_rx(void)
{
	int prevfrag, nowready;
	struct ac97_frame* fragp;

//	if (!(DMA3->IRQ_STATUS & DMA_DONE))
//		return -EINPROGRESS;

	prevfrag = set_current_rx_fragment();
	decfrag(&prevfrag);

	fragp = dev.rxbuf + prevfrag*dev.fragsize;

	nowready = fragp[0].ac97_tag & TAG_VALID;


#if defined(AC97_SPORT_DEBUG)
	if (nowready != dev.codec_ready)
		printk(KERN_INFO "ac97_sport: Codec state changed to"
				" '%sready'\n", (nowready) ? "" : "not " );
#endif
	dev.codec_ready = nowready;

	if (dev.codec_ready)
		wake_up(&dev.audio_in_wait); /* wake up any proces waiting for at least 1 fragment */

	dev.rx_lastfrag = prevfrag; /* last fragment handled by irq */

	DMA3->IRQ_STATUS = DMA_DONE;

	return 0;
}



int ac97_sport_handle_tx(void)
{
	int i;

	if (!(DMA4->IRQ_STATUS & DMA_DONE))
		return -EINPROGRESS;

	if (dev.codec_ready) {

		int prevfrag = set_current_tx_fragment();

		if (!dev.codec_initialized) {
#ifdef AC97_SPORT_DEBUG
			printk(KERN_INFO "ac97_sport: Sending initialization commands.\n");
#endif
			init_ac97();
	}

		prevfrag = set_current_tx_fragment(); // ???
		decfrag(&prevfrag);

		while (dev.tx_lastfrag != prevfrag) {
			struct ac97_frame* fragp;

			incfrag(&dev.tx_lastfrag);
			fragp =  dev.txbuf + dev.tx_lastfrag*dev.fragsize;

			for (i=0; i<dev.cmd_count[dev.tx_lastfrag]; i++)
				fragp[i].ac97_tag = TAG_VALID | TAG_PCM;

			dev.cmd_count[dev.tx_lastfrag] = 0;

		}

		dev.tx_lastfrag = prevfrag;
		wake_up(&dev.audio_out_wait);
	} // codec ready

	DMA4->IRQ_STATUS = DMA_DONE;

	return 0;
} // handle tx





// enqueue to send 'set register <reg> to <val>' command,
// followed by 'read <reg>' command
// marking the register cache 'dirty'
// the receive routine will update the register cache when the answer
// arrives

int ac97_sport_set_register(int reg, __u16 val)
{
	if ((reg < 0) || (reg > 127) || (reg & 0x1))
		return -EINVAL;

	enqueue_cmd( reg << 8,           val); // write
	enqueue_cmd((reg << 8) | 0x8000, 0  ); // read back

	reg_set_dirty(reg);

	return 0; // ok!
}


// get it from the cache, retval indicates wether it was dirty or not

int ac97_sport_get_register(int reg, __u16 *pval)
{
	if ((reg < 0) || (reg > 127) || (reg & 0x1))
		return -EINVAL;

	*pval = dev.register_cache[reg];

	if (reg_is_dirty(reg))
		return -EAGAIN;

	return 0;
}



/*
 * copy audio data from/to userspace to our rx/tx buf
 * note: len is in units of __u16's
 * if len will not fit in buffer, these will not transfer data and return -EAGAIN
 */


static int rx_used(void)
{
	long bytes = ((unsigned long)DMA3->CURR_ADDR - (unsigned long)(dev.rxbuf + dev.rx_tail));
	int frames = bytes >> LOG_BYTES_PER_FRAME;

	if (frames < 0)
		frames += dev.bufsize;

	return frames;
}


static int tx_used(void)
{
	long bytes = ((unsigned long)(dev.txbuf+dev.tx_head) - (u32)(DMA4->CURR_ADDR));
	int frames = bytes >> LOG_BYTES_PER_FRAME;

	if (frames<0)
		frames += dev.bufsize;

	return frames;
}

/* note implicit in next few lines: 1 sample per frame */
#define BYTES_PER_SAMPLE	sizeof(__u32)
#define LOG_BYTES_PER_SAMPLE	2
ssize_t ac97_audio_read_min_bytes(void)
{
	return rx_used() * BYTES_PER_SAMPLE;
}

ssize_t ac97_audio_write_max_bytes(void)
{
	int write_max = (dev.bufsize - tx_used() - dev.fragsize);
	if (write_max < 0) write_max = 0;
	return write_max * BYTES_PER_SAMPLE;
}

int rx_would_underflow(ssize_t bytes_to_read)
{
	return ac97_audio_read_min_bytes() < bytes_to_read;
}

int tx_would_overflow(ssize_t bytes_to_write)
{
	return ac97_audio_write_max_bytes() < bytes_to_write;
}


// mem2mem dma?  zero overhead loop?
static void move_frames_to_continuous(__u32 *dest, struct ac97_frame *src, size_t count)
{
	while(count--)
		*(dest++) = (src++)->ac97_pcm;
}


/* check for overflow or underflow before calling this */
/* stereo data means 1 uint_32 per sample (and we have 1 sample per frame */
ssize_t ac97_sport_get_pcm_to_user(uint32_t *pcmdata, size_t /* sample_ */ count)
{
	int cnt = count;

	if ((dev.rx_tail + count) >= dev.bufsize) {

		count = dev.bufsize - dev.rx_tail;

 		if (count) {
			move_frames_to_continuous(pcmdata, dev.rxbuf+dev.rx_tail, count);
			pcmdata += count;
		}
		count = cnt - count;
		dev.rx_tail = 0;

	}

	if (count) {
		move_frames_to_continuous(pcmdata, dev.rxbuf+dev.rx_tail, count );
		dev.rx_tail += count;
	}

	return cnt;
}

ssize_t ac97_audio_read(uint8_t *pcmdata, size_t len)
{
	int samples_to_read, samples_read, bytes_read = 0;

	if (!rx_would_underflow(len)) {
		samples_to_read = len >> LOG_BYTES_PER_SAMPLE;
		samples_read = ac97_sport_get_pcm_to_user((uint32_t*)pcmdata, samples_to_read);
		bytes_read = samples_read << LOG_BYTES_PER_SAMPLE;
	}
	return bytes_read;
}

static void move_continuous_to_frames(struct ac97_frame *dest, const __u32 *src, size_t count)
{
	while (count--) {
		 dest->ac97_tag |= TAG_VALID | TAG_PCM; /* ?  mh */
		(dest++)->ac97_pcm = *(src++);
	}
}

/* check for overflow or underflow before calling this */
ssize_t ac97_sport_put_pcm_from_user(const uint32_t *pcmdata, size_t count)
{
	int cnt = count;

	if ((dev.tx_head + count) >= dev.bufsize) {

		count = dev.bufsize - dev.tx_head;

		if (count) {
			move_continuous_to_frames(dev.txbuf+dev.tx_head, pcmdata, count);
			pcmdata += count;
		}
		count = cnt-count;
		dev.tx_head = 0;
	}

	if (count) {
		move_continuous_to_frames(dev.txbuf+dev.tx_head, pcmdata, count);
		dev.tx_head += count;
	}

	return cnt;
}

ssize_t ac97_audio_write(const uint8_t *pcmdata, size_t len)
{
	int samples_to_write, samples_written, bytes_written = 0;

	if (!tx_would_overflow(len)) {
		samples_to_write = len >> LOG_BYTES_PER_SAMPLE;
		samples_written = ac97_sport_put_pcm_from_user((uint32_t*)pcmdata, samples_to_write);
		bytes_written = samples_written << LOG_BYTES_PER_SAMPLE;
	}
	return bytes_written;
}

void ac97_sport_silence(void)
{
	int i;
	for (i=0; i<dev.bufsize; ++i)
		dev.txbuf[i].ac97_pcm = 0;
}


int ac97_wait_for_audio_read_with_timeout(unsigned long timeout)
{
	return interruptible_sleep_on_timeout(&dev.audio_in_wait, timeout);
}

int ac97_wait_for_audio_write_with_timeout(unsigned long timeout)
{
	return interruptible_sleep_on_timeout(&dev.audio_out_wait, timeout);
}


wait_queue_head_t *ac97_get_read_waitqueue(void)
{
	return &dev.audio_in_wait;
}

wait_queue_head_t *ac97_get_write_waitqueue(void)
{
	return &dev.audio_out_wait;
}
