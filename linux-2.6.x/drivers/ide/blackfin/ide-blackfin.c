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
#include <linux/irq.h>
#include <linux/config.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/delay.h>
#include <asm/blackfin.h>

#define CF_ATASEL_ENA	CONFIG_CF_ATASEL_ENA
#define CF_ATASEL_DIS	CONFIG_CF_ATASEL_DIS


#if defined(CONFIG_BFIN_IDE_ADDRESS_MAPPING_MODE0)
  #define BFIN_IDE_GAP CONFIG_BFIN_IDE_GAP
  #define AX_BITMASK 0
#endif

#if defined(CONFIG_BFIN_IDE_ADDRESS_MAPPING_MODE1)
  #define BFIN_IDE_GAP (1)
  #define AX_BITMASK (1<<CONFIG_BFIN_IDE_ADDRESS_AX)
#endif


static inline void hw_setup(hw_regs_t *hw)
{
	int i,x;

	memset(hw, 0, sizeof(hw_regs_t));
	for (i = 0; i <= IDE_STATUS_OFFSET; i++){
#if defined(CONFIG_BFIN_IDE_ADDRESS_MAPPING_MODE1)
	  if(i & 0x1){
	    x = i & -2;
	    x |= AX_BITMASK;
	  }
	  else
#endif
	  x=i;
	  hw->io_ports[i] = CONFIG_BFIN_IDE_BASE + BFIN_IDE_GAP*x;
	}

	hw->io_ports[IDE_CONTROL_OFFSET] = CONFIG_BFIN_IDE_ALT;
	hw->irq = CONFIG_BFIN_IDE_IRQ_PFX;
	hw->dma = NO_DMA;
	hw->chipset = ide_generic;
}

static inline void hwif_setup(ide_hwif_t *hwif)
{
	default_hwif_iops(hwif);

	hwif->mmio  = 2;
	hwif->OUTL  = NULL;
	hwif->INL   = NULL;
	hwif->OUTSL = NULL;
	hwif->INSL  = NULL;
}


void __init blackfin_ide_init(void)
{
	hw_regs_t hw;
	ide_hwif_t *hwif;
	int idx;

#if defined(CONFIG_BFIN_IDE_ADDRESS_MAPPING_MODE1)
	  outw(0, CF_ATASEL_ENA);
	  udelay(5000);
#endif

	if (!request_region(CONFIG_BFIN_IDE_BASE, AX_BITMASK + BFIN_IDE_GAP*8, "ide-blackfin"))
		goto out_busy;
	if (!request_region(CONFIG_BFIN_IDE_ALT, BFIN_IDE_GAP, "ide-blackfin")) {
		release_region(CONFIG_BFIN_IDE_BASE, BFIN_IDE_GAP*2);
		goto out_busy;
	}

	hw_setup(&hw);

	set_irq_type(hw.irq, IRQF_TRIGGER_HIGH);

	/* register if */
	idx = ide_register_hw(&hw, &hwif);
	if (idx == -1) {
		printk(KERN_ERR "ide-Blackfin: IDE I/F register failed\n");
		return;
	}

	hwif_setup(hwif);
        create_proc_ide_interfaces();

	printk(KERN_INFO "ide%d: Blackfin generic IDE interface\n", idx);
	return;

out_busy:
	printk(KERN_ERR "ide-blackfin: IDE I/F resource already used.\n");
}
