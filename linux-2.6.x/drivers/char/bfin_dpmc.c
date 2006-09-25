/*
 * File:         drivers/char/bfin_dpmc.c
 * Based on:
 * Author:
 *
 * Created:
 * Description:
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright 2004-2006 Analog Devices Inc.
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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/miscdevice.h>
#include <linux/ioport.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#include <linux/rtc.h>

#include <asm/blackfin.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <asm/dpmc.h>
#include "bfin_dpmc.h"
#include <asm/delay.h>

#undef DPMC_DEBUG

#ifdef DPMC_DEBUG
#define DPRINTK(x...)	printk(KERN_DEBUG x)
#else
#define DPRINTK(x...)	do { } while (0)
#endif

unsigned long SDRAM_tRP1;
unsigned long SDRAM_tRAS1;
unsigned long SDRAM_tRCD1;
unsigned long SDRAM_tWR1;

#if 0
static unsigned long F_Changed_Freq_Act = 0;
#endif

unsigned long get_sdrrcval(unsigned long sc)
{
	unsigned long SCLK = sc;
	unsigned long SDRAM_tRP=0;
	unsigned long SDRAM_tRAS=0;
	unsigned long SDRAM_tRCD=0;
	unsigned long SDRAM_tWR=0;
	unsigned long sdrrcval;

	unsigned long sdval1 = 119402985;
	unsigned long sdval2 = 104477612;
	unsigned long sdval3 = 89552239;
	unsigned long sdval4 = 74626866;
	unsigned long sdval5 = 66666667;
	unsigned long sdval6 = 59701493;
	unsigned long sdval7 = 44776119;
	unsigned long sdval8 = 29850746;

	if (SCLK > sdval1) {
		SDRAM_tRP  = 2;
		SDRAM_tRAS = 7;
		SDRAM_tRCD = 2;
		SDRAM_tWR  = 2;

		SDRAM_tRP1  = TRP_2;
		SDRAM_tRAS1 = TRAS_7;
		SDRAM_tRCD1 = TRCD_2;
		SDRAM_tWR1  = TWR_2;

	} else if ((SCLK > sdval2) && (SCLK <= sdval1)) {
		SDRAM_tRP  = 2;
		SDRAM_tRAS = 6;
		SDRAM_tRCD = 2;
		SDRAM_tWR  = 2;

		SDRAM_tRP1  = TRP_2;
		SDRAM_tRAS1 = TRAS_6;
		SDRAM_tRCD1 = TRCD_2;
		SDRAM_tWR1  = TWR_2;

	} else if ((SCLK > sdval3) && (SCLK <= sdval2)) {
		SDRAM_tRP  = 2;
		SDRAM_tRAS = 5;
		SDRAM_tRCD = 2;
		SDRAM_tWR  = 2;

		SDRAM_tRP1  = TRP_2;
		SDRAM_tRAS1 = TRAS_5;
		SDRAM_tRCD1 = TRCD_2;
		SDRAM_tWR1  = TWR_2;

	} else if ((SCLK > sdval4) && (SCLK <=  sdval3)) {
		SDRAM_tRP  = 2;
		SDRAM_tRAS = 4;
		SDRAM_tRCD = 2;
		SDRAM_tWR  = 2;

		SDRAM_tRP1  = TRP_2;
		SDRAM_tRAS1 = TRAS_4;
		SDRAM_tRCD1 = TRCD_2;
		SDRAM_tWR1  = TWR_2;

	} else if ((SCLK > sdval5) && (SCLK <= sdval4)) {
		SDRAM_tRP  = 2;
		SDRAM_tRAS = 3;
		SDRAM_tRCD = 2;
		SDRAM_tWR  = 2;

		SDRAM_tRP1  = TRP_2;
		SDRAM_tRAS1 = TRAS_3;
		SDRAM_tRCD1 = TRCD_2;
		SDRAM_tWR1  = TWR_2;

	} else if ((SCLK >  sdval6) && (SCLK <= sdval5)) {
		SDRAM_tRP  = 1;
		SDRAM_tRAS = 4;
		SDRAM_tRCD = 1;
		SDRAM_tWR  = 2;

		SDRAM_tRP1  = TRP_1;
		SDRAM_tRAS1 = TRAS_4;
		SDRAM_tRCD1 = TRCD_1;
		SDRAM_tWR1  = TWR_2;

	} else if ((SCLK >  sdval7) && (SCLK <=  sdval6)) {
		SDRAM_tRP  = 1;
		SDRAM_tRAS = 3;
		SDRAM_tRCD = 1;
		SDRAM_tWR  = 2;

		SDRAM_tRP1  = TRP_1;
		SDRAM_tRAS1 = TRAS_3;
		SDRAM_tRCD1 = TRCD_1;
		SDRAM_tWR1  = TWR_2;

	} else if ((SCLK >  sdval8) && (SCLK <= sdval7)) {
		SDRAM_tRP  = 1;
		SDRAM_tRAS = 2;
		SDRAM_tRCD = 1;
		SDRAM_tWR  = 2;

		SDRAM_tRP1  = TRP_1;
		SDRAM_tRAS1 = TRAS_2;
		SDRAM_tRCD1 = TRCD_1;
		SDRAM_tWR1  = TWR_2;

	} else if (SCLK <=  sdval8) {
		SDRAM_tRP  = 1;
		SDRAM_tRAS = 1;
		SDRAM_tRCD = 1;
		SDRAM_tWR  = 2;

		SDRAM_tRP1  = TRP_1;
		SDRAM_tRAS1 = TRAS_1;
		SDRAM_tRCD1 = TRCD_1;
		SDRAM_tWR1  = TWR_2;
	}

	SCLK = SCLK / MHZ;
	sdrrcval = (((SCLK * 1000 * SDRAM_Tref) / SDRAM_NRA) - (SDRAM_tRAS + SDRAM_tRP));

	return sdrrcval;
}

int get_closest_ssel(int a, int b, int c, unsigned long vco, unsigned long clock)
{
	int t1, t2, t3;

	t1 = abs(clock - (vco/a));
	t2 = abs(clock - (vco/b));
	t3 = abs(clock - (vco/c));

	if ((t1 < t2) && (t1 < t3))
		return a;
	else if ((t2 < t1) && (t2 < t3))
		return b;
	else
		return c;
}

unsigned long change_sclk(unsigned long clock)
{
	int ssel,ret;
	unsigned long vco;

	clock = clock * MHZ;
	vco = get_vco();
	ssel = vco/clock;

	/* Check nearest frequency to which it can be set to */
	ssel = get_closest_ssel(ssel, ssel-1, ssel+1, vco, clock);
	if (ssel == 0)
		ssel = 1;

	if (ssel > MAX_SSEL) {
		DPRINTK("Selecting ssel = 15\n");
		ssel = MAX_SSEL;
	}
	__builtin_bfin_ssync();
	bfin_write_EBIU_SDGCTL(bfin_read_EBIU_SDGCTL() | SRFS);
	__builtin_bfin_ssync();

	ret = set_pll_div(ssel,FLAG_SSEL);

#ifdef DPMC_DEBUG
	if (ret < 0)
		DPRINTK("Wrong system clock selection\n");
#endif

	bfin_write_EBIU_SDRRC(get_sdrrcval(get_sclk()));
	__builtin_bfin_ssync();

	/* Get SDRAM out of self refresh mode */
	bfin_write_EBIU_SDGCTL(bfin_read_EBIU_SDGCTL() & ~SRFS);
	__builtin_bfin_ssync();

	/* May not be required */
#if 0
	bfin_read_EBIU_SDGCTL() = (bfin_read_EBIU_SDGCTL() | SCTLE | CL_2 | SDRAM_tRAS1 | SDRAM_tRP1 | SDRAM_tRCD1 | SDRAM_tWR1);
	__builtin_bfin_ssync();
#endif

	return(get_sclk());
}

static int dpmc_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
	unsigned long cclk_mhz=0,sclk_mhz=0,vco_mhz=0,pll_stat=0,vco_mhz_bk,mvolt,wdog_tm=0;
	/* struct bf533_serial *in; */

	switch (cmd) {
		case IOCTL_FULL_ON_MODE:
			fullon_mode();
#if 0
			if (F_Changed_Freq_Act) {
				change_core_clock(get_vco()/MHZ);
				if ((get_vco()/(DEF_SSEL * MHZ)) < (MIN_SCLK/MHZ))
					sclk_mhz = change_sclk(MIN_SCLK/MHZ);
				else
					sclk_mhz = change_sclk((get_vco()/(DEF_SSEL * MHZ)));
				F_Changed_Freq_Act = 0;
			}
			change_baud(CONSOLE_BAUD_RATE);
#endif
			change_baud(CONSOLE_BAUD_RATE);
			bfin_write_SIC_IWR(IWR_ENABLE_ALL);
			__builtin_bfin_ssync();

			break;

		case IOCTL_ACTIVE_MODE:
			active_mode();
			change_baud(CONSOLE_BAUD_RATE);
			bfin_write_SIC_IWR(IWR_ENABLE_ALL);
			__builtin_bfin_ssync();
			break;

		case IOCTL_SLEEP_MODE:
			sleep_mode(IWR_ENABLE(IRQ_RTC - IVG7));
			bfin_write_SIC_IWR(IWR_ENABLE_ALL);
			__builtin_bfin_ssync();
			break;

		case IOCTL_DEEP_SLEEP_MODE:
			deep_sleep(IWR_ENABLE(IRQ_RTC - IVG7));

/* Active Mode SCLK = CCLK is hazardous condition Anomlay 05000273 */
/* Changed deep_sleep to return to Full On Mode */
#if 0
			/* Needed since it comes back to active mode */
			change_baud(CONSOLE_BAUD_RATE);
#endif
			bfin_write_SIC_IWR(IWR_ENABLE_ALL);
			__builtin_bfin_ssync();
			break;

		case IOCTL_SLEEP_DEEPER_MODE:
			sleep_deeper(IWR_ENABLE(IRQ_RTC - IVG7));
			bfin_write_SIC_IWR(IWR_ENABLE_ALL);
			__builtin_bfin_ssync();
			break;

		case IOCTL_HIBERNATE_MODE:
			hibernate_mode(IWR_ENABLE(IRQ_RTC - IVG7));
			bfin_write_SIC_IWR(IWR_ENABLE_ALL);
			__builtin_bfin_ssync();
			break;

		case IOCTL_CHANGE_FREQUENCY:
			copy_from_user(&vco_mhz,(unsigned long *)arg,sizeof(unsigned long));
			vco_mhz_bk = vco_mhz;
			if ((vco_mhz > MAX_VCO) || (vco_mhz < MIN_VCO))
				return -1;
			if (get_pll_status() & 0x1)
				return -1;
#if 0
			if (get_pll_status() & 0x1) {
				F_Changed_Freq_Act = 1;
				vco_mhz = change_frequency(vco_mhz_bk/MHZ);
				copy_to_user((unsigned long *)arg, &vco_mhz, sizeof(unsigned long));
				break;
			}
#endif
			/* This is done to avoid drastic change of frequency since it affects SSEL.
			 * At 135MHz keeping SSEL as 5 or 1 does not matter 
			 */
			if (vco_mhz > INTER_FREQ) {
				vco_mhz = change_frequency(INTER_FREQ/MHZ);
				change_core_clock(vco_mhz/MHZ);
				if ((vco_mhz/(DEF_SSEL * MHZ)) < (MIN_SCLK/MHZ)) {
					DPRINTK("System clock being changed to minimum\n");
					sclk_mhz = change_sclk((MIN_SCLK/MHZ));
				} else
					sclk_mhz = change_sclk((vco_mhz/(DEF_SSEL * MHZ)));
				change_baud(CONSOLE_BAUD_RATE);

				vco_mhz = change_frequency(vco_mhz_bk/MHZ);
				change_core_clock(vco_mhz/MHZ);
				if ((vco_mhz/(DEF_SSEL * MHZ)) < (MIN_SCLK/MHZ)) {
					DPRINTK("System clock being changed to minimum\n");
					sclk_mhz = change_sclk((MIN_SCLK/MHZ));
				} else
					sclk_mhz = change_sclk((vco_mhz/(DEF_SSEL * MHZ)));
				change_baud(CONSOLE_BAUD_RATE);

			} else {
				vco_mhz = change_frequency(vco_mhz_bk/MHZ);
				change_core_clock(vco_mhz/MHZ);
				if ((vco_mhz/(DEF_SSEL * MHZ)) < (MIN_SCLK/MHZ)) {
					DPRINTK("System clock being changed to minimum\n");
					sclk_mhz = change_sclk(MIN_SCLK/MHZ);
				} else
					sclk_mhz = change_sclk((vco_mhz/(DEF_SSEL * MHZ)));
				change_baud(CONSOLE_BAUD_RATE);
			}
			bfin_write_SIC_IWR(IWR_ENABLE_ALL);
			__builtin_bfin_ssync();
			copy_to_user((unsigned long *)arg, &vco_mhz, sizeof(unsigned long));
			break;

		case IOCTL_CHANGE_VOLTAGE:
			if (!(get_pll_status() & 0x2))
				return -1;
			copy_from_user(&mvolt,(unsigned long *)arg,sizeof(unsigned long));
			if ((mvolt >= MIN_VOLT) && (mvolt <= MAX_VOLT) && ((mvolt%50) == 0))
				mvolt = change_voltage(mvolt);
			else {
				printk(KERN_NOTICE "Selected voltage not valid\n");
				return -1;
			}
			copy_to_user((unsigned long *)arg, &mvolt, sizeof(unsigned long));
			break;

		case IOCTL_SET_CCLK:
			if (get_pll_status() & 0x1)
				return -1;
			copy_from_user(&cclk_mhz,(unsigned long *)arg,sizeof(unsigned long));
			if (get_vco() < cclk_mhz)
				return -1;
			if (cclk_mhz <= get_sclk()) {
				DPRINTK("Sorry, core clock has to be greater than system clock\n");
				DPRINTK("Current System Clock is %u MHz\n",get_sclk()/1000000);
				return -1;
			}
			cclk_mhz = change_core_clock(cclk_mhz/MHZ);
			copy_to_user((unsigned long *)arg, &cclk_mhz, sizeof(unsigned long));
			break;

		case IOCTL_SET_SCLK:
			if (get_pll_status() & 0x1)
				return -1;
			copy_from_user(&sclk_mhz,(unsigned long *)arg,sizeof(unsigned long));
			if ((get_vco() < sclk_mhz) || (sclk_mhz >= get_cclk()) || \
			    (sclk_mhz > MAX_SCLK) || (sclk_mhz < MIN_SCLK))
				return -1;
			sclk_mhz = change_sclk(sclk_mhz/MHZ);
			change_baud(CONSOLE_BAUD_RATE);
			copy_to_user((unsigned long *)arg, &sclk_mhz, sizeof(unsigned long));
			break;

		case IOCTL_GET_PLLSTATUS:
			pll_stat = get_pll_status();
			copy_to_user((unsigned long *)arg, &pll_stat, sizeof(unsigned long));
			break;

		case IOCTL_GET_CORECLOCK:
			cclk_mhz = get_cclk();
			copy_to_user((unsigned long *)arg, &cclk_mhz, sizeof(unsigned long));
			break;

		case IOCTL_GET_SYSTEMCLOCK:
			sclk_mhz = get_sclk();
			copy_to_user((unsigned long *)arg, &sclk_mhz, sizeof(unsigned long));
			break;

		case IOCTL_GET_VCO:
			vco_mhz = get_vco();
			copy_to_user((unsigned long *)arg, &vco_mhz, sizeof(unsigned long));
			break;

		case IOCTL_DISABLE_WDOG_TIMER:
			disable_wdog_timer();
			if (bfin_read_WDOG_CTL() == TMR_DIS)
				return 0;
			else
				return -1;
			break;

		case IOCTL_UNMASK_WDOG_WAKEUP_EVENT:
			unmask_wdog_wakeup_evt();
			break;

		case IOCTL_PROGRAM_WDOG_TIMER:
			copy_from_user(&wdog_tm,(unsigned long *)arg,sizeof(unsigned long));
			program_wdog_timer(wdog_tm);
			if (bfin_read_WDOG_CNT() == wdog_tm)
				return 0;
			else
				return -1;
			break;

		case IOCTL_CLEAR_WDOG_WAKEUP_EVENT:
			clear_wdog_wakeup_evt();
			if (bfin_read_WDOG_CTL() & 0x8000)
				return -1;
			else
				return 0;
			break;
	}

	return 0;
}

void change_baud(int baud)
{
	int uartdll,sclk;
	unsigned long flags;

	local_irq_save(flags);

	/* If in active mode sclk and cclk run at CCLKIN*/
	if (get_pll_status() & 0x1)
		sclk = CONFIG_CLKIN_HZ;
	else
		sclk = get_sclk();

	uartdll = sclk/(16*baud);
	bfin_write_UART_LCR(DLAB);
	__builtin_bfin_ssync();
	bfin_write_UART_DLL(uartdll & 0xFF);
	__builtin_bfin_ssync();
	bfin_write_UART_DLH((uartdll >> 8));
	__builtin_bfin_ssync();
	bfin_write_UART_LCR(WLS(8));
	__builtin_bfin_ssync();

	local_irq_restore(flags);
}

/*********************************************************************************/

/* Read the PLL_STAT register */
unsigned long get_pll_status(void)
{
	return bfin_read_PLL_STAT();
}

/* Change the core clock - PLL_DIV register */
unsigned long change_core_clock(unsigned long clock)
{
	int tempcsel,csel,ret;
	unsigned long vco;

	clock = clock * MHZ;
	vco = get_vco();
	tempcsel = vco/clock;

	if (tempcsel == 1)
		csel = 0;
	else if (tempcsel == 2)
		csel = 1;
	else if (tempcsel == 4)
		csel = 2;
	else if (tempcsel == 8)
		csel = 3;
	else {
		DPRINTK("Wrong core clock selection\n");
		DPRINTK("Selecting clock to be same as VCO\n");
		csel = 0;
	}
	ret = set_pll_div(csel,FLAG_CSEL);

#ifdef DPMC_DEBUG
	if (ret < 0)
		DPRINTK("Wrong core clock selection\n");
#endif

	return get_cclk();
}

/* Returns VCO in Hz */
int get_vco(void)
{
	return ((CONFIG_CLKIN_HZ) * ((*(volatile unsigned short *)PLL_CTL >> 9)& 0x3F));
}

/* Sets the PLL_DIV register CSEL or SSEL bits depending on flag */
int set_pll_div(unsigned short sel, unsigned char flag)
{
	if(flag == FLAG_CSEL) {
		if(sel <= 3) {
			bfin_write_PLL_DIV((bfin_read_PLL_DIV() & 0xCF) | (sel << 4));
			__builtin_bfin_ssync();
			return 0;
		} else {
			DPRINTK("CCLK value selected not valid\n");
			return -1;
		}
	} else if(flag == FLAG_SSEL){
		if (sel < 16) {
			bfin_write_PLL_DIV((bfin_read_PLL_DIV() & 0xF0) | sel);
			__builtin_bfin_ssync();
			return 0;
		} else {
			DPRINTK("SCLK value selected not valid\n");
			return -1;
		}
	}
	return -1;
}

unsigned long change_frequency(unsigned long vco_mhz)
{
#if 0 /* This is broken - You can't put SDRAM into Self Refresh and then execute from SDRAM */
#if 0
	unsigned long sdrrcval,modeval;
#endif
	unsigned long vco_hz = vco_mhz * MHZ,vl;
	int msel;
	unsigned long flags;

	msel = calc_msel(vco_hz);
	msel = (msel << 9);

/* Enable the PLL Wakeup bit in SIC IWR */
	bfin_write_SIC_IWR(IWR_ENABLE(0));
	__builtin_bfin_ssync();

	bfin_write_PLL_LOCKCNT(0x300);
	__builtin_bfin_ssync();

	__builtin_bfin_ssync();
	bfin_read_EBIU_SDGCTL() = (bfin_read_EBIU_SDGCTL() | SRFS);
	__builtin_bfin_ssync();

	vl = bfin_read_PLL_CTL();
	__builtin_bfin_ssync();
	vl &= 0x81FF;
	msel |= vl;

	bfin_write_PLL_CTL(msel);
	__builtin_bfin_ssync();

	local_irq_save(flags);
	__builtin_bfin_ssync();
	asm("IDLE;");
	local_irq_restore(flags);

	while (!(bfin_read_PLL_STAT() & PLL_LOCKED))
		;

	bfin_write_EBIU_SDRRC(get_sdrrcval((get_sclk())));
	__builtin_bfin_ssync();

	bfin_read_EBIU_SDGCTL() = bfin_read_EBIU_SDGCTL() & ~SRFS;
	__builtin_bfin_ssync();

#if 0
	 bfin_write_EBIU_SDGCTL((SCTLE | CL_2 | SDRAM_tRAS1 | SDRAM_tRP1 | SDRAM_tRCD1 | SDRAM_tWR1));
	__builtin_bfin_ssync();
#endif

#if 0
	/* May not be required */
	if (bfin_read_EBIU_SDSTAT() & SDRS) {

		bfin_write_EBIU_SDRRC(get_sdrrcval((get_sclk()*MHZ)));
		__builtin_bfin_ssync();

		bfin_write_EBIU_SDBCTL(0x13);
		__builtin_bfin_ssync();

		modeval = (SCTLE | CL_2 | SDRAM_tRAS1 | SDRAM_tRP1 | SDRAM_tRCD1 | SDRAM_tWR1 | PSS);
		bfin_write_EBIU_SDGCTL(modeval);
		__builtin_bfin_ssync();
	}
#endif

#endif

	return (get_vco());
}

int calc_msel(int vco_hz)
{
	if (vco_hz%(CONFIG_CLKIN_HZ))
		return (vco_hz/(CONFIG_CLKIN_HZ) + 1);
	else
		return (vco_hz/(CONFIG_CLKIN_HZ));
}

void fullon_mode(void)	{

#if 0 /* This is broken - You can't put SDRAM into Self Refresh and then execute from SDRAM */ 
	unsigned long flags;

	bfin_write_SIC_IWR(IWR_ENABLE(0));
	__builtin_bfin_ssync();

	bfin_write_PLL_LOCKCNT(0x300);
	__builtin_bfin_ssync();

	__builtin_bfin_ssync();
	bfin_write_EBIU_SDGCTL(bfin_read_EBIU_SDGCTL() | SRFS);
	__builtin_bfin_ssync();

/* Together if done, some issues with code generation,so split this way*/
	bfin_write_PLL_CTL(bfin_read_PLL_CTL() & (unsigned short)~(BYPASS));
	bfin_write_PLL_CTL(bfin_read_PLL_CTL() & (unsigned short)~(PDWN));
	bfin_write_PLL_CTL(bfin_read_PLL_CTL() & (unsigned short)~(STOPCK_OFF));
	bfin_write_PLL_CTL(bfin_read_PLL_CTL() & (unsigned short)~(PLL_OFF));
	__builtin_bfin_ssync();

	local_irq_save(flags);
	__builtin_bfin_ssync();
	asm("IDLE;");
	local_irq_restore(flags);

	while((bfin_read_PLL_STAT() & PLL_LOCKED) != PLL_LOCKED);

	bfin_write_EBIU_SDRRC(get_sdrrcval(get_sclk()));
	__builtin_bfin_ssync();

	bfin_write_EBIU_SDGCTL(bfin_read_EBIU_SDGCTL() & ~SRFS);
	__builtin_bfin_ssync();

#endif
}

void active_mode(void)
{
#if 0 /* This is broken - You can't put SDRAM into Self Refresh and then execute from SDRAM */ 
	  /* In addition in BYPASS mode SCLK = CCLK which is hazardous condition Anomlay 05000273 */
	unsigned long flags;

	bfin_write_SIC_IWR(IWR_ENABLE(0));
	__builtin_bfin_ssync();

	bfin_write_PLL_LOCKCNT(0x300);
	__builtin_bfin_ssync();

	__builtin_bfin_ssync();
	bfin_write_EBIU_SDGCTL(bfin_read_EBIU_SDGCTL() | SRFS);
	__builtin_bfin_ssync();

	bfin_write_PLL_CTL(bfin_read_PLL_CTL() | BYPASS);
	__builtin_bfin_ssync();

	local_irq_save(flags);
	__builtin_bfin_ssync();
	asm("IDLE;");
	local_irq_restore(flags);

	while((bfin_read_PLL_STAT() & PLL_LOCKED) != PLL_LOCKED)
		;

	bfin_write_EBIU_SDRRC(get_sdrrcval(get_sclk()));
	__builtin_bfin_ssync();

	bfin_write_EBIU_SDGCTL(bfin_read_EBIU_SDGCTL() & ~SRFS);
	__builtin_bfin_ssync();
#endif
}

/********************************CHANGE OF VOLTAGE*******************************************/

/*
VLEV Voltage
0000–0101 Reserved
0110 .85 volts
0111 .90 volts
1000 .95 volts
1001 1.00 volts
1010 1.05 volts
1011 1.10 volts
1100 1.15 volts
1101 1.20 volts
1110 1.25 volts
1111 1.30 volts
*/

/* Calculates the VLEV value for VR_CTL programming*/
unsigned long calc_volt()
{
	int base = 850;
	int val = ((bfin_read_VR_CTL() >> 4) & 0xF);

	if (val == 6)
		return base;

	DPRINTK("calc_volt() returning %u \n",(((val - 6) * 50) + base));
	return (((val - 6) * 50) + base);
}

/* Change the voltage of the processor */
unsigned long change_voltage(unsigned long volt)
{
	unsigned long vlt,val,flags;

	vlt = calc_vlev(volt);
	val = (bfin_read_VR_CTL() & 0xFF0F);
	val = (val | (vlt << 4));
	bfin_write_VR_CTL(val);

	while(!(get_pll_status() & VOLTAGE_REGULATED))
		;

	return(calc_volt());
}

/* Calculates the voltage at which the processor is running */
int calc_vlev(int vlt)
{
	int base = 6;
	if (vlt == 850)
		return base;
	else
		return (((vlt - 850)/50) + base);
}


/*
 *  We enforce only one user at a time here with the open/close.
 *  Also clear the previous interrupt data on an open, and clean
 *  up things on a close.
 */

/* We use dpmc_lock to protect against concurrent opens.*/
static int dpmc_open(struct inode *inode, struct file *file)
{
	//DPRINTK("DPMC Device Opening");
	return 0;
}

static int dpmc_release(struct inode *inode, struct file *file)
{
	return 0;
}

/*
 *  The various file operations we support.
 */
struct file_operations dpmc_fops = {
	owner:      THIS_MODULE,
	llseek:     dpmc_llseek,
	read:       dpmc_read,
	ioctl:      dpmc_ioctl,
	open:       dpmc_open,
	release:    dpmc_release
};

static struct miscdevice dpmc_dev = {
	DPMC_MINOR,
	"dpmc",
	&dpmc_fops
};

/* Init function called first time */
int __init dpmc_init(void)
{
	struct proc_dir_entry *entry;

	DPRINTK("blackfin_dpmc_init\n");

	misc_register(&dpmc_dev);

	if ((entry = create_proc_entry("driver/dpmc_suspend", 0, NULL)) == NULL) {
		printk(KERN_ERR "%s: unable to create /proc entry\n", __FUNCTION__);
	} else {
		entry->read_proc = dpmc_read_proc;
		entry->write_proc = dpmc_write_proc;
		entry->data = NULL;
	}

	printk(KERN_INFO "Dynamic Power Management Controller Driver v" DPMC_VERSION ": major=%d, minor = %d\n", MISC_MAJOR, DPMC_MINOR);
	return 0;
}

void __exit dpmc_exit (void)
{
	remove_proc_entry ("driver/dpmc_suspend", NULL);
	misc_deregister(&dpmc_dev);
}

module_init(dpmc_init);
module_exit(dpmc_exit);

static int dpmc_write_proc(struct file *file, const char __user * buffer,
                           unsigned long count, void *data)
{
	s8 line[16];
	u32 val=0;

	if (count <= 16){
		copy_from_user(line, buffer, count);
		val = simple_strtoul(line, NULL, 0);
	}

	if (val) {
		sleep_deeper(val);
		bfin_write_SIC_IWR(IWR_ENABLE_ALL);
	}

	return count;
}


static int dpmc_read_proc(char *page, char **start, off_t off,
                         int count, int *eof, void *data)
{
	return -1;
}

static loff_t dpmc_llseek(struct file *file, loff_t offset, int origin)
{
	return -ESPIPE;
}

static ssize_t dpmc_read(struct file *file, char *buf,
            size_t count, loff_t *ppos)
{
	return -1;
}

unsigned long mult(unsigned long x)
{
	return (x*1000000);
}
