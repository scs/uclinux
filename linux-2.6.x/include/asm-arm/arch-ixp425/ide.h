/*
 * linux/include/asm-arm/arch-ixp425/ide.h
 *
 * Copyright (c) 1998 Russell King
 *
 * Modifications:
 *  29-07-1998	RMK	Major re-work of IDE architecture specific code
 */

#include <asm/irq.h>

/*
 * Set up a hw structure for a specified data port, control port and IRQ.
 * This should follow whatever the default interface uses.
 */
static __inline__ void
ide_init_hwif_ports(hw_regs_t *hw, int data_port, int ctrl_port, int *irq)
{
	ide_ioreg_t reg = (ide_ioreg_t) data_port;
	int i;

	for (i = IDE_DATA_OFFSET; i <= IDE_STATUS_OFFSET; i++) {
		hw->io_ports[i] = reg;
		reg += 1;
	}
	hw->io_ports[IDE_CONTROL_OFFSET] = (ide_ioreg_t) ctrl_port;
	if (irq)
		*irq = 0;
}

/*
 * This registers the standard ports for this architecture with the IDE
 * driver.
 */
static __inline__ void ide_init_default_hwifs(void)
{
	/* There are no standard ports */
}

/*
 *	We need to swap the raw data stream, since for the programmed
 *	I/O case it is swap by the PCI bus unit. For registers this is
 *	no problem (since we are running big-endian, we need to swap),
 *	no good for raw data streams though, they are now backwords.
 *	For the IDE case we need only swap 16bit reads/writes, sinec
 *	they are the data channel reads/writes.
 */
#undef	insw
#undef	outsw

static __inline__ u16 swap16(u16 val)
{
	return ((val << 8) | (val >> 8));
}

static __inline__ void insw(u32 port, u16 *addr, u32 count)
{
	while (count--)
		*addr++ = swap16(inw(port));
}

static __inline__ void outsw(u32 port, u16 *addr, u32 count)
{
	while (count--)
		outw(swap16(*addr++), port);
}

