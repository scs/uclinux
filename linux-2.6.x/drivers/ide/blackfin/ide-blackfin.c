/*
 * file: drivers/ide/ide-blackfin.c
 * based on: drivers/ide/ide-h8300.c
 * author: Michael Hennerich (hennerich@blackfin.uclinux.org)
 *
 * created: 10/2005
 * description: Blackfin generic IDE interface
 *	
 * rev: 
 *
 * modified:
 *
 *
 * bugs:         enter bugs at http://blackfin.uclinux.org/
 *
 * this program is free software; you can redistribute it and/or modify
 * it under the terms of the gnu general public license as published by
 * the free software foundation; either version 2, or (at your option)
 * any later version.
 *
 * this program is distributed in the hope that it will be useful,
 * but without any warranty; without even the implied warranty of
 * merchantability or fitness for a particular purpose.  see the
 * gnu general public license for more details.
 *
 * you should have received a copy of the gnu general public license
 * along with this program; see the file copying.
 * if not, write to the free software foundation,
 * 59 temple place - suite 330, boston, ma 02111-1307, usa.
 */

#include <linux/init.h>
#include <linux/ide.h>
#include <linux/config.h>

#include <asm/io.h>
#include <asm/irq.h>

static void ide_outw(u16 d, unsigned long a)
{

	writew(d,a);

}

static u16 ide_inw(unsigned long a)
{

	return readw(a);
}

static void ide_outsw(unsigned long addr, void *buf, u32 len)
{
	outsw(addr,buf,len);
}

static void ide_insw(unsigned long addr, void *buf, u32 len)
{
	insw(addr,buf,len);
}

#define BFIN_IDE_GAP (2)

static inline void hw_setup(hw_regs_t *hw)
{
	int i;

	memset(hw, 0, sizeof(hw_regs_t));
	for (i = 0; i <= IDE_STATUS_OFFSET; i++)
		hw->io_ports[i] = CONFIG_BFIN_IDE_BASE + BFIN_IDE_GAP*i;
	hw->io_ports[IDE_CONTROL_OFFSET] = CONFIG_BFIN_IDE_ALT;
	hw->irq = CONFIG_BFIN_IDE_IRQ;
	hw->dma = NO_DMA;
	hw->chipset = ide_generic;
}

static inline void hwif_setup(ide_hwif_t *hwif)
{
	default_hwif_iops(hwif);

	hwif->mmio  = 2;
	hwif->OUTW  = ide_outw;
	hwif->OUTSW = ide_outsw;
	hwif->INW   = ide_inw;
	hwif->INSW  = ide_insw;
	hwif->OUTL  = NULL;
	hwif->INL   = NULL;
	hwif->OUTSL = NULL;
	hwif->INSL  = NULL;
}

static void bfin_IDE_interrupt_setup(int irq)
{

#ifdef CONFIG_IRQCHIP_DEMUX_GPIO
    printk("Blackfin IDE interrupt setup: DEMUX_GPIO irq %d\n", irq);
    set_irq_type(irq, IRQT_HIGH);
#else
    unsigned short flag,portx_fer;
    unsigned short IDE_FIO_PATTERN;

    if (CONFIG_BFIN_IDE_IRQ_PFX < IRQ_PF0 || CONFIG_BFIN_IDE_IRQ_PFX > IRQ_PF15) {
	printk(KERN_ERR "irq_pfx out of range: %d\n", CONFIG_BFIN_IDE_IRQ_PFX);
	return;
    }

    flag = CONFIG_BFIN_IDE_IRQ_PFX - IRQ_PF0;
    IDE_FIO_PATTERN = (1 << flag);

#if defined(CONFIG_BF534)|defined(CONFIG_BF536)|defined(CONFIG_BF537)
  portx_fer = *pPORT_FER;
  *pPORT_FER = portx_fer & ~IDE_FIO_PATTERN;
  __builtin_bfin_ssync();
#endif

    printk("Blackfin IDE interrupt setup: flag PF%d, irq %d\n", flag, irq);
  /* 26 = IRQ_PROG_INTA => FIO_MASKA
     27 = IRQ_PROG_INTB => FIO_MASKB */
  if (irq == IRQ_PROG_INTA/*26*/ ||
      irq == IRQ_PROG_INTB/*27*/)
    {
      int ixab = (irq - IRQ_PROG_INTA) * (pFIO_MASKB_D - pFIO_MASKA_D);

      __builtin_bfin_csync();
      pFIO_MASKA_C[ixab] = IDE_FIO_PATTERN; /* disable int */
      __builtin_bfin_ssync();

      *pFIO_POLAR &= ~IDE_FIO_PATTERN; /* active high (input) */
      *pFIO_EDGE  &= ~IDE_FIO_PATTERN; /* by level (input) */
      *pFIO_BOTH  &= ~IDE_FIO_PATTERN; 

      *pFIO_DIR  &= ~IDE_FIO_PATTERN;   /* input */
      *pFIO_FLAG_C = IDE_FIO_PATTERN;   /* clear output */
      *pFIO_INEN |=  IDE_FIO_PATTERN;   /* enable pin */

      __builtin_bfin_ssync();
      pFIO_MASKA_S[ixab] = IDE_FIO_PATTERN; /* enable int */
    }
#endif /*CONFIG_IRQCHIP_DEMUX_GPIO*/

}

void __init blackfin_ide_init(void)
{
	hw_regs_t hw;
	ide_hwif_t *hwif;
	int idx;


	if (!request_region(CONFIG_BFIN_IDE_BASE, BFIN_IDE_GAP*8, "ide-blackfin"))
		goto out_busy;
	if (!request_region(CONFIG_BFIN_IDE_ALT, BFIN_IDE_GAP, "ide-blackfin")) {
		release_region(CONFIG_BFIN_IDE_BASE, BFIN_IDE_GAP*8);
		goto out_busy;
	}

	hw_setup(&hw);

	bfin_IDE_interrupt_setup(CONFIG_BFIN_IDE_IRQ);

	/* register if */
	idx = ide_register_hw(&hw, &hwif);
	if (idx == -1) {
		printk(KERN_ERR "ide-Blackfin: IDE I/F register failed\n");
		return;
	}

	hwif_setup(hwif);
	printk(KERN_INFO "ide%d: Blackfin generic IDE interface\n", idx);
	return;

out_busy:
	printk(KERN_ERR "ide-blackfin: IDE I/F resource already used.\n");
}
