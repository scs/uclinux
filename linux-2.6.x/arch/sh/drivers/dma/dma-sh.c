/*
 * arch/sh/kernel/cpu/dma.c
 *
 * Copyright (C) 2000 Takashi YOSHII
 * Copyright (C) 2003 Paul Mundt
 *
 * PC like DMA API for SuperH's DMAC.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */

#include <linux/config.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <asm/signal.h>
#include <asm/irq.h>
#include <asm/dma.h>
#include <asm/io.h>
#include "dma-sh.h"

/*
 * The SuperH DMAC supports a number of transmit sizes, we list them here,
 * with their respective values as they appear in the CHCR registers.
 *
 * Defaults to a 64-bit transfer size.
 */
enum {
	XMIT_SZ_64BIT	= 0,
	XMIT_SZ_8BIT	= 1,
	XMIT_SZ_16BIT	= 2,
	XMIT_SZ_32BIT	= 3,
	XMIT_SZ_256BIT	= 4,
};

/*
 * The DMA count is defined as the number of bytes to transfer.
 */
static unsigned int ts_shift[] = {
	[XMIT_SZ_64BIT]		3,
	[XMIT_SZ_8BIT]		0,
	[XMIT_SZ_16BIT]		1,
	[XMIT_SZ_32BIT]		2,
	[XMIT_SZ_256BIT]	5,
};

/*
 * We determine the correct shift size based off of the CHCR transmit size
 * for the given channel. Since we know that it will take:
 *
 * 	info->count >> ts_shift[transmit_size]
 *
 * iterations to complete the transfer.
 */
static inline unsigned int calc_xmit_shift(struct dma_info *info)
{
	return ts_shift[(ctrl_inl(CHCR[info->chan]) >> 4) & 0x0007];
}

static irqreturn_t dma_tei(int irq, void *dev_id, struct pt_regs *regs)
{
	int chan = irq - DMTE0_IRQ;
	struct dma_info *info = get_dma_info(chan);

	if (info->sar)
		ctrl_outl(info->sar, SAR[info->chan]);
	if (info->dar)
		ctrl_outl(info->dar, DAR[info->chan]);

	ctrl_outl(info->count >> calc_xmit_shift(info), DMATCR[info->chan]);
	ctrl_outl(ctrl_inl(CHCR[info->chan]) & ~CHCR_TE, CHCR[info->chan]);

	disable_irq(irq);

	return IRQ_HANDLED;
}

static struct irqaction irq_tei = {
	.name		= "DMAC Transfer End",
	.handler	= dma_tei,
	.flags		= SA_INTERRUPT,
};

static int sh_dmac_request_dma(struct dma_info *info)
{
	int irq = DMTE0_IRQ + info->chan;

	make_ipr_irq(irq, DMA_IPR_ADDR, DMA_IPR_POS, DMA_PRIORITY);
	return setup_irq(irq, &irq_tei);
}

static void sh_dmac_free_dma(struct dma_info *info)
{
	free_irq(DMTE0_IRQ + info->chan, 0);
}

static void sh_dmac_configure_channel(struct dma_info *info, unsigned long chcr)
{
	if (!chcr) {
		chcr = ctrl_inl(CHCR[info->chan]);
		chcr |= /* CHCR_IE | */ RS_DUAL;
	}

	ctrl_outl(chcr, CHCR[info->chan]);

	info->configured = 1;
}

static void sh_dmac_enable_dma(struct dma_info *info)
{
	unsigned long chcr;

	chcr = ctrl_inl(CHCR[info->chan]);
	chcr |= CHCR_DE;
	ctrl_outl(chcr, CHCR[info->chan]);
}

static void sh_dmac_disable_dma(struct dma_info *info)
{
	unsigned long chcr;

	chcr = ctrl_inl(CHCR[info->chan]);
	chcr &= ~(CHCR_DE | CHCR_TE);
	ctrl_outl(chcr, CHCR[info->chan]);
}

static int sh_dmac_xfer_dma(struct dma_info *info)
{
	/* 
	 * If we haven't pre-configured the channel with special flags, use
	 * the defaults.
	 */
	if (!info->configured)
		sh_dmac_configure_channel(info, 0);

	sh_dmac_disable_dma(info);
	
	/* 
	 * Single-address mode usage note!
	 *
	 * It's important that we don't accidentally write any value to SAR/DAR
	 * (this includes 0) that hasn't been directly specified by the user if
	 * we're in single-address mode.
	 *
	 * In this case, only one address can be defined, anything else will
	 * result in a DMA address error interrupt (at least on the SH-4),
	 * which will subsequently halt the transfer.
	 */
	if (info->sar)
		ctrl_outl(info->sar, SAR[info->chan]);
	if (info->dar)
		ctrl_outl(info->dar, DAR[info->chan]);
	
	ctrl_outl(info->count >> calc_xmit_shift(info), DMATCR[info->chan]);

	sh_dmac_enable_dma(info);

	return 0;
}

static int sh_dmac_get_dma_residue(struct dma_info *info)
{
	return (ctrl_inl(DMATCR[info->chan]) << calc_xmit_shift(info));
}

#if defined(CONFIG_CPU_SH4)
static irqreturn_t dma_err(int irq, void *dev_id, struct pt_regs *regs)
{
	printk("DMAE: DMAOR=%x\n",ctrl_inl(DMAOR));
	ctrl_outl(ctrl_inl(DMAOR)&~DMAOR_NMIF, DMAOR);
	ctrl_outl(ctrl_inl(DMAOR)&~DMAOR_AE, DMAOR);
	ctrl_outl(ctrl_inl(DMAOR)|DMAOR_DME, DMAOR);

	disable_irq(irq);

	return IRQ_HANDLED;
}

static struct irqaction irq_err = {
	.name		= "DMAC Address Error",
	.handler	= dma_err,
	.flags		= SA_INTERRUPT,
};
#endif

static struct dma_ops sh_dmac_ops = {
	.name		= "SuperH DMAC",
	.request	= sh_dmac_request_dma,
	.free		= sh_dmac_free_dma,
	.get_residue	= sh_dmac_get_dma_residue,
	.xfer		= sh_dmac_xfer_dma,
	.configure	= sh_dmac_configure_channel,
};
	
static int __init sh_dmac_init(void)
{
	unsigned long dmaor;
	int i;

#ifdef CONFIG_CPU_SH4
	make_ipr_irq(DMAE_IRQ, DMA_IPR_ADDR, DMA_IPR_POS, DMA_PRIORITY);
	setup_irq(DMAE_IRQ, &irq_err);
#endif

	/* Kick the DMAOR */
	dmaor = ctrl_inl(DMAOR);
	dmaor |= DMAOR_DME | /* 0x200 |*/ 0x8000; /* DDT = 1, PR1 = 1, DME = 1 */
	dmaor &= ~(DMAOR_NMIF | DMAOR_AE);
	ctrl_outl(dmaor, DMAOR);

	for (i = 0; i < MAX_DMA_CHANNELS; i++)
		dma_info[i].ops  = &sh_dmac_ops;

	return register_dmac(&sh_dmac_ops);
}

static void __exit sh_dmac_exit(void)
{
#ifdef CONFIG_CPU_SH4
	free_irq(DMAE_IRQ, 0);
#endif
}

subsys_initcall(sh_dmac_init);
module_exit(sh_dmac_exit);

MODULE_LICENSE("GPL");

