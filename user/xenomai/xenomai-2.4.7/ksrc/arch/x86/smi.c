/**
 *   @ingroup hal
 *   @file
 *
 *   SMI workaround for x86.
 *
 *   Cut/Pasted from Vitor Angelo "smi" module.
 *   Adapted by Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/reboot.h>
#include <asm/xenomai/hal.h>

/* DEVICE_IDs needed for 2.4 support */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
#ifndef PCI_DEVICE_ID_INTEL_ICH7_0
#define PCI_DEVICE_ID_INTEL_ICH7_0 0x27b8
#define PCI_DEVICE_ID_INTEL_ICH7_1 0x27b9
#endif
#ifndef PCI_DEVICE_ID_INTEL_ICH8_4
#define PCI_DEVICE_ID_INTEL_ICH8_4 0x2815
#endif
#endif

static struct pci_device_id rthal_smi_pci_tbl[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82801AA_0)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82801AB_0)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82801BA_0)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82801BA_10)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82801E_0)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82801CA_0)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82801CA_12)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82801DB_0)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82801DB_12)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82801EB_0)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_ICH6_0)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_ICH6_1)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_ICH6_2)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_ICH7_0)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_ICH7_1)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_ICH8_4)},
	{0,},
};

/* FIXME: Probably crippled too, need to be checked :

0x24dc 82801EB (ICH5) LPC Interface Bridge (not a real ID, but exists in the
pci.ids database, ICH5-M ?)
{ PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82801EB_12, PCI_ANY_ID, PCI_ANY_ID, },

*/

#define DEVFN        0xf8	/* device 31, function 0 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define pci_get_device(v,d,f) pci_find_device((v),(d),(f))
#define pci_dev_put(d)        do { } while(0)
#endif

#ifdef CONFIG_XENO_HW_SMI_WORKAROUND

#define PMBASE_B0    0x40
#define PMBASE_B1    0x41

#define SMI_CTRL_ADDR    0x30
#define SMI_STATUS_ADDR  0x34
#define SMI_MON_ADDR     0x40

/* SMI_EN register: ICH[0](16 bits), ICH[2-5](32 bits) */
#define INTEL_USB2_EN_BIT   (0x01 << 18)	/* ICH4, ... */
#define LEGACY_USB2_EN_BIT  (0x01 << 17)	/* ICH4, ... */
#define PERIODIC_EN_BIT     (0x01 << 14)	/* called 1MIN_ in ICH0 */
#define TCO_EN_BIT          (0x01 << 13)
#define MCSMI_EN_BIT        (0x01 << 11)
#define SWSMI_TMR_EN_BIT    (0x01 << 6)
#define APMC_EN_BIT         (0x01 << 5)
#define SLP_EN_BIT          (0x01 << 4)
#define LEGACY_USB_EN_BIT   (0x01 << 3)
#define BIOS_EN_BIT         (0x01 << 2)
#define GBL_SMI_EN_BIT      (0x01)	/* This is reset by a PCI reset event! */

static const unsigned rthal_smi_masked_bits =
#ifdef CONFIG_XENO_HW_SMI_ALL
    GBL_SMI_EN_BIT;
#else /* !defined(CONFIG_XENO_HW_SMI_ALL) */
    0
#ifndef CONFIG_XENO_HW_SMI_INTEL_USB2
    | INTEL_USB2_EN_BIT
#endif /* !defined(CONFIG_XENO_HW_SMI_INTEL_USB2) */
#ifndef CONFIG_XENO_HW_SMI_LEGACY_USB2
    | LEGACY_USB2_EN_BIT
#endif /* !defined(CONFIG_XENO_HW_SMI_LEGACY_USB2) */
#ifndef CONFIG_XENO_HW_SMI_PERIODIC
    | PERIODIC_EN_BIT
#endif /* !defined(CONFIG_XENO_HW_SMI_PERIODC) */
#ifndef CONFIG_XENO_HW_SMI_TCO
    | TCO_EN_BIT
#endif /* !defined(CONFIG_XENO_HW_SMI_TCO) */
#ifndef CONFIG_XENO_HW_SMI_MC
    | MCSMI_EN_BIT
#endif /* !defined(CONFIG_XENO_HW_SMI_MCSMI) */
#ifndef CONFIG_XENO_HW_SMI_APMC
    | APMC_EN_BIT
#endif /* !defined(CONFIG_XENO_HW_SMI_APMC) */
#ifndef CONFIG_XENO_HW_SMI_LEGACY_USB
    | LEGACY_USB_EN_BIT
#endif /* !defined(CONFIG_XENO_HW_SMI_LEGACY_USB) */
#ifndef CONFIG_XENO_HW_SMI_BIOS
    | BIOS_EN_BIT
#endif /* !defined(CONFIG_XENO_HW_SMI_BIOS) */
    ;

#endif /* !defined(CONFIG_XENO_HW_SMI_ALL) */

static unsigned rthal_smi_saved_bits;
static unsigned short rthal_smi_en_addr;

#define mask_bits(v, p) outl(inl(p)&~(v),(p))
#define set_bits(v, p)  outl(inl(p)|(v), (p))

static int rthal_smi_reboot(struct notifier_block *nb, ulong event, void *buf);

static struct notifier_block rthal_smi_notifier = {
	.notifier_call = rthal_smi_reboot
};

static int rthal_smi_reboot(struct notifier_block *nb, ulong event, void *buf)
{
	if (((event == SYS_RESTART) || (event == SYS_HALT) ||
	     (event == SYS_POWER_OFF)) && rthal_smi_en_addr)
		set_bits(rthal_smi_saved_bits, rthal_smi_en_addr);

	return NOTIFY_DONE;
}

void rthal_smi_disable(void)
{
	if (!rthal_smi_en_addr)
		return;

	rthal_smi_saved_bits = inl(rthal_smi_en_addr) & rthal_smi_masked_bits;
	mask_bits(rthal_smi_masked_bits, rthal_smi_en_addr);

	if (inl(rthal_smi_en_addr) & rthal_smi_masked_bits)
		printk("Xenomai: SMI workaround failed!\n");
	else
		printk("Xenomai: SMI workaround enabled\n");

	register_reboot_notifier(&rthal_smi_notifier);
}

void rthal_smi_restore(void)
{
	if (!rthal_smi_en_addr)
		return;

	printk("Xenomai: SMI configuration restored\n");

	set_bits(rthal_smi_saved_bits, rthal_smi_en_addr);

	unregister_reboot_notifier(&rthal_smi_notifier);
}

static unsigned short get_smi_en_addr(struct pci_dev *dev)
{
	u_int8_t byte0, byte1;

	pci_read_config_byte(dev, PMBASE_B0, &byte0);
	pci_read_config_byte(dev, PMBASE_B1, &byte1);
	return SMI_CTRL_ADDR + (((byte1 << 1) | (byte0 >> 7)) << 7);	// bits 7-15
}

#endif /* CONFIG_XENO_HW_SMI_WORKAROUND */

void rthal_smi_init(void)
{
	struct pci_dev *dev = NULL;
	struct pci_device_id *id;

	/*
	 * Do not use pci_register_driver, pci_enable_device, ...
	 * Just register the used ports.
	 */
	for (id = &rthal_smi_pci_tbl[0]; dev == NULL && id->vendor != 0; id++)
		dev = pci_get_device(id->vendor, id->device, NULL);

	if (dev == NULL || dev->bus->number || dev->devfn != DEVFN) {
		pci_dev_put(dev);
		return;
	}
#ifdef CONFIG_XENO_HW_SMI_WORKAROUND
	printk("Xenomai: SMI-enabled chipset found\n");
	rthal_smi_en_addr = get_smi_en_addr(dev);
#else /* ! CONFIG_XENO_HW_SMI_WORKAROUND */
	printk
	    ("Xenomai: SMI-enabled chipset found, but SMI workaround disabled\n"
	     "         (check CONFIG_XENO_HW_SMI_WORKAROUND). You may encounter\n"
	     "         high interrupt latencies!\n");
#endif /* ! CONFIG_XENO_HW_SMI_WORKAROUND */

	pci_dev_put(dev);
}

#ifdef CONFIG_XENO_HW_SMI_DETECT
EXPORT_SYMBOL(rthal_smi_init);
#endif /* CONFIG_XENO_HW_SMI_DETECT */

#if defined(CONFIG_XENO_HW_SMI_DETECT) && defined(CONFIG_XENO_HW_SMI_WORKAROUND)
EXPORT_SYMBOL(rthal_smi_disable);
EXPORT_SYMBOL(rthal_smi_restore);
#endif /* !CONFIG_XENO_HW_SMI_DETECT || !CONFIG_XENO_HW_SMI_WORKAROUND */

/*

   FIXME: there are many more SMI sources than those of the SMI_EN
   register. From http://www.intel.com/design/chipsets/datashts/252516.htm
   there are at least the following other sources :

   pages 377, 386, 388, 389; Power management
       register GEN_PMCON1, bit SMI_LOCK, locks GLB_SMI_EN
       bits PER_SMI_SEL, allow selection of the periodic SMI
       registers PM1_STS, PM1_EN, PM1_CNT bit SCI_EN, if cleared generates SMI
       for power management events.

   pages 173, 381, 400; GPIOs
       register GPI[0-15]_ROUT allow routing each GPIO to SMI or SCI
       register ALT_GP_SMI_EN, ALT_GP_SMI_STS, allow masking SMIs for GPIOs

   pages 184, 188, 402; legacy devices emulation (ATA, floppy, parallel, UARTs,
       keyboard). I/O to specified ports may cause events, which can generate an
       SMI, depending on registers configuration :
       register DEVTRAP_EN, DEVTRAP_STS
       BIG FAT WARNING : globally disabling SMI on a box with SATA disks and
           SATA controller in "legacy" mode, probably prevents disks from
           working.

   pages 382, 383, 400; Monitors ?
       seem to be a generic legacy device emulation (like previous), registers
       MON[4-7]_FWD_EN, enables forwarding of I/O to LPC
       MON[4-7]_TRP_RNG, address of the emulated devices
       MON[4-7]_TRP_MSK and MON_SMI (registers MON[4-7]_TRAP_EN and
                                     MON[4-7]_TRAP_STS)

   page 407: TCO
       register TCO1_CNT, bit NMI2SMI_EN, enables TCO to use SMI instead of NMI,
       bit TCO_TMR_HLT, should be cleared to avoid being rebooted when the TCO
       timer expires. Dangerous bit: TCO_LOCK locks the TCO timer until reboot.
       register used by Linux drivers/char/watchdog/i8xx_tco.c

   page 492, 493: USB EHCI legacy support and SPECIAL SMI, i.e Intel Specific
       USB 2.0 SMI register.
       
   page 520, SMBus
       may be disabled by clearing register HOSTC, bit SMB_SMI_EN
       register used by Linux driver drivers/i2c/busses/i2c-i801.c

*/
