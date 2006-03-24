#include <linux/config.h>
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

	if(SCLK > sdval1) {
		SDRAM_tRP  = 2;
		SDRAM_tRAS = 7;
		SDRAM_tRCD = 2;
		SDRAM_tWR  = 2;

		SDRAM_tRP1  = TRP_2;
		SDRAM_tRAS1 = TRAS_7;
		SDRAM_tRCD1 = TRCD_2;
		SDRAM_tWR1  = TWR_2;
	}
	else if(( SCLK > sdval2 ) && ( SCLK <= sdval1)) {
	SDRAM_tRP  = 2;
	SDRAM_tRAS = 6;
	SDRAM_tRCD = 2;
	SDRAM_tWR  = 2;

	SDRAM_tRP1  = TRP_2;
	SDRAM_tRAS1 = TRAS_6;
	SDRAM_tRCD1 = TRCD_2;
	SDRAM_tWR1  = TWR_2;

	}
	else if (( SCLK > sdval3 ) && ( SCLK <= sdval2 )) {
	SDRAM_tRP  = 2;
	SDRAM_tRAS = 5;
	SDRAM_tRCD = 2;
	SDRAM_tWR  = 2;

	SDRAM_tRP1  = TRP_2;
	SDRAM_tRAS1 = TRAS_5;
	SDRAM_tRCD1 = TRCD_2;
	SDRAM_tWR1  = TWR_2;	
	}
	else if (( SCLK > sdval4 ) && ( SCLK <=  sdval3 )) {
	SDRAM_tRP  = 2;
	SDRAM_tRAS = 4;
	SDRAM_tRCD = 2;
	SDRAM_tWR  = 2;

	SDRAM_tRP1  = TRP_2;
	SDRAM_tRAS1 = TRAS_4;
	SDRAM_tRCD1 = TRCD_2;
	SDRAM_tWR1  = TWR_2;

	}
	else if (( SCLK > sdval5 ) && ( SCLK <= sdval4 )) {
	SDRAM_tRP  = 2;
	SDRAM_tRAS = 3;
	SDRAM_tRCD = 2;
	SDRAM_tWR  = 2;

	SDRAM_tRP1  = TRP_2;
	SDRAM_tRAS1 = TRAS_3;
	SDRAM_tRCD1 = TRCD_2;
	SDRAM_tWR1  = TWR_2;


	}
	else if (( SCLK >  sdval6 ) && ( SCLK <= sdval5 )) {
	SDRAM_tRP  = 1;
	SDRAM_tRAS = 4;
	SDRAM_tRCD = 1;
	SDRAM_tWR  = 2;

	SDRAM_tRP1  = TRP_1;
	SDRAM_tRAS1 = TRAS_4;
	SDRAM_tRCD1 = TRCD_1;
	SDRAM_tWR1  = TWR_2;

	}
	else if (( SCLK >  sdval7 ) && ( SCLK <=  sdval6 )) {
	SDRAM_tRP  = 1;
	SDRAM_tRAS = 3;
	SDRAM_tRCD = 1;
	SDRAM_tWR  = 2;

	SDRAM_tRP1  = TRP_1;
	SDRAM_tRAS1 = TRAS_3;
	SDRAM_tRCD1 = TRCD_1;
	SDRAM_tWR1  = TWR_2;

	}
	else if (( SCLK >  sdval8 ) && ( SCLK <= sdval7 )) {
	SDRAM_tRP  = 1;
	SDRAM_tRAS = 2;
	SDRAM_tRCD = 1;
	SDRAM_tWR  = 2;

	SDRAM_tRP1  = TRP_1;
	SDRAM_tRAS1 = TRAS_2;
	SDRAM_tRCD1 = TRCD_1;
	SDRAM_tWR1  = TWR_2;

	}
	else if ( SCLK <=  sdval8 ) {
	SDRAM_tRP  = 1;
	SDRAM_tRAS = 1;
	SDRAM_tRCD = 1;
	SDRAM_tWR  = 2;

	SDRAM_tRP1  = TRP_1;
	SDRAM_tRAS1 = TRAS_1;
	SDRAM_tRCD1 = TRCD_1;
	SDRAM_tWR1  = TWR_2;

	}

	SCLK = SCLK/MHZ;
	sdrrcval = (((SCLK * 1000 * SDRAM_Tref)/SDRAM_NRA) - (SDRAM_tRAS + SDRAM_tRP));

	return sdrrcval;
}

int get_closest_ssel(int a,int b,int c,unsigned long vco,unsigned long clock)
{
	int t1,t2,t3;

	t1 = abs(clock - (vco/a));
	t2 = abs(clock - (vco/b));
	t3 = abs(clock - (vco/c));
	
	if((t1 < t2) && (t1 < t3))
		return a;
	else if((t2 < t1) && (t2 < t3))
		return b;
	else	return c;
}

unsigned long change_sclk(unsigned long clock)
{
	int ssel,ret;
	unsigned long vco;

	clock = clock * MHZ;
	vco = get_vco();
	ssel = vco/clock;

	/* Check nearest frequency to which it can be set to */	
	ssel = get_closest_ssel(ssel,ssel-1,ssel+1,vco,clock);
	if(ssel == 0)	ssel = 1;

	if(ssel > MAX_SSEL) {
#if DPMC_DEBUG
		printk("Selecting ssel = 15 \n");
#endif
		ssel = MAX_SSEL;
	}
	__builtin_bfin_ssync();
	*pEBIU_SDGCTL = (*pEBIU_SDGCTL | SRFS);
	__builtin_bfin_ssync();

	ret = set_pll_div(ssel,FLAG_SSEL);

#if DPMC_DEBUG
	if(ret < 0)
		printk("Wrong system clock selection \n");
#endif

	*pEBIU_SDRRC = get_sdrrcval(get_sclk());
	__builtin_bfin_ssync();

	/* Get SDRAM out of self refresh mode */
	*pEBIU_SDGCTL = (*pEBIU_SDGCTL & ~SRFS);
	__builtin_bfin_ssync();

	/* May not be required */
#if 0
	*pEBIU_SDGCTL = (*pEBIU_SDGCTL | SCTLE | CL_2  | SDRAM_tRAS1  | SDRAM_tRP1  | SDRAM_tRCD1  | SDRAM_tWR1);
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
			if(F_Changed_Freq_Act) {
				change_core_clock(get_vco()/MHZ);
                                if((get_vco()/(DEF_SSEL * MHZ)) < (MIN_SCLK/MHZ))
                                        sclk_mhz = change_sclk(MIN_SCLK/MHZ);
                                else
                                        sclk_mhz = change_sclk((get_vco()/(DEF_SSEL * MHZ)));
				F_Changed_Freq_Act = 0;
			}
			change_baud(CONSOLE_BAUD_RATE);
#endif
			change_baud(CONSOLE_BAUD_RATE);
			*pSIC_IWR = IWR_ENABLE_ALL;
			__builtin_bfin_ssync();

		break;

		case IOCTL_ACTIVE_MODE:
			active_mode();
			change_baud(CONSOLE_BAUD_RATE);
			*pSIC_IWR = IWR_ENABLE_ALL;
			__builtin_bfin_ssync();

		break;
		case IOCTL_SLEEP_MODE:
			sleep_mode();
			*pSIC_IWR = IWR_ENABLE_ALL;
			__builtin_bfin_ssync();
		break;				

		case IOCTL_DEEP_SLEEP_MODE:
			deep_sleep();
			/* Needed since it comes back to active mode */
			change_baud(CONSOLE_BAUD_RATE);
			*pSIC_IWR = IWR_ENABLE_ALL;
			__builtin_bfin_ssync();
		break;
		
		case IOCTL_HIBERNATE_MODE:
			hibernate_mode();
			*pSIC_IWR = IWR_ENABLE_ALL;
			__builtin_bfin_ssync();
		break;

		case IOCTL_CHANGE_FREQUENCY:
			copy_from_user(&vco_mhz,(unsigned long *)arg,sizeof(unsigned long));
			vco_mhz_bk = vco_mhz;
			if((vco_mhz > MAX_VCO) || (vco_mhz < MIN_VCO))	return -1;			
			if(get_pll_status() & 0x1)			return -1;
#if 0
			if(get_pll_status() & 0x1) {
				F_Changed_Freq_Act = 1;
				vco_mhz = change_frequency(vco_mhz_bk/MHZ);
	    			copy_to_user((unsigned long *)arg, &vco_mhz, sizeof(unsigned long));
				break;
			}
#endif
			/* This is done to avoid drastic change of frequency since it affects SSEL.
			 * At 135MHz keeping SSEL as 5 or 1 does not matter 
			 */
			if(vco_mhz > INTER_FREQ) {
				vco_mhz = change_frequency(INTER_FREQ/MHZ);
				change_core_clock(vco_mhz/MHZ);
				if((vco_mhz/(DEF_SSEL * MHZ)) < (MIN_SCLK/MHZ)) {
#if DPMC_DEBUG
					printk("System clock being changed to minimum \n");
#endif
					sclk_mhz = change_sclk((MIN_SCLK/MHZ));
				}
				else
					sclk_mhz = change_sclk((vco_mhz/(DEF_SSEL * MHZ)));
				change_baud(CONSOLE_BAUD_RATE);

				vco_mhz = change_frequency(vco_mhz_bk/MHZ);
				change_core_clock(vco_mhz/MHZ);
				if((vco_mhz/(DEF_SSEL * MHZ)) < (MIN_SCLK/MHZ)) {
#if DPMC_DEBUG
					printk("System clock being changed to minimum \n");
#endif
					sclk_mhz = change_sclk((MIN_SCLK/MHZ));
				}
				else
					sclk_mhz = change_sclk((vco_mhz/(DEF_SSEL * MHZ)));
				change_baud(CONSOLE_BAUD_RATE);
			}
			else {
				vco_mhz = change_frequency(vco_mhz_bk/MHZ);
				change_core_clock(vco_mhz/MHZ);
				if((vco_mhz/(DEF_SSEL * MHZ)) < (MIN_SCLK/MHZ)) {
#if DPMC_DEBUG
					printk("System clock being changed to minimum \n");
#endif
					sclk_mhz = change_sclk(MIN_SCLK/MHZ);
					
				}
				else
					sclk_mhz = change_sclk((vco_mhz/(DEF_SSEL * MHZ)));
				change_baud(CONSOLE_BAUD_RATE);
			}
			*pSIC_IWR = IWR_ENABLE_ALL;
			__builtin_bfin_ssync();
	    		copy_to_user((unsigned long *)arg, &vco_mhz, sizeof(unsigned long));
		break;
		case IOCTL_CHANGE_VOLTAGE:
			if(!(get_pll_status() & 0x2))	return -1;
			copy_from_user(&mvolt,(unsigned long *)arg,sizeof(unsigned long));
			if((mvolt >= MIN_VOLT) && (mvolt <= MAX_VOLT) && ((mvolt%50) == 0))
				mvolt = change_voltage(mvolt);
			else {
				printk("Selected voltage not valid \n");
				return -1;
			}
    			copy_to_user((unsigned long *)arg, &mvolt, sizeof(unsigned long));
		break;
		case IOCTL_SET_CCLK:
			if(get_pll_status() & 0x1)	return -1;
			copy_from_user(&cclk_mhz,(unsigned long *)arg,sizeof(unsigned long));
			if(get_vco() < cclk_mhz)	return -1;
			if(cclk_mhz <= get_sclk()) {
#if DPMC_DEBUG
				printk("Sorry, core clock has to be greater than system clock\n");
				printk("Current System Clock is %u MHz\n",get_sclk()/1000000);
#endif
				return -1;
			}
			cclk_mhz = change_core_clock(cclk_mhz/MHZ);
	    		copy_to_user((unsigned long *)arg, &cclk_mhz, sizeof(unsigned long));
		break;

		case IOCTL_SET_SCLK:
			if(get_pll_status() & 0x1)	return -1;
			copy_from_user(&sclk_mhz,(unsigned long *)arg,sizeof(unsigned long));
			if(get_vco() < sclk_mhz)	return -1;
			if(sclk_mhz >= get_cclk())		return -1;
			if(sclk_mhz > MAX_SCLK)			return -1;
			if(sclk_mhz < MIN_SCLK)			return -1;
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
			if(*pWDOG_CTL == WDOG_DISABLE)	return 0;
			else 				return -1;
		break;
		
		case IOCTL_UNMASK_WDOG_WAKEUP_EVENT:
			unmask_wdog_wakeup_evt();
		break;
		
		case IOCTL_PROGRAM_WDOG_TIMER:
			copy_from_user(&wdog_tm,(unsigned long *)arg,sizeof(unsigned long));
			program_wdog_timer(wdog_tm);
			if(*pWDOG_CNT == wdog_tm)	return 0;
			else 				return -1;
		break;

		case IOCTL_CLEAR_WDOG_WAKEUP_EVENT:
			clear_wdog_wakeup_evt();
			if(*pWDOG_CTL & 0x8000)	return -1;
			else 			return 0;
		break;				
	}
	return 0;	
}

void change_baud(int baud)      {
        int uartdll,sclk;

	asm("[--sp] = r6;"
	"cli r6;");	

	/* If in active mode sclk and cclk run at CCLKIN*/
	if(get_pll_status() & 0x1)	sclk = CONFIG_CLKIN_HZ;
	else				sclk = get_sclk();
	
        uartdll = sclk/(16*baud);
        *pUART_LCR = DLAB;
	__builtin_bfin_ssync();
        *pUART_DLL = (uartdll & 0xFF);
	__builtin_bfin_ssync();
        *pUART_DLH = (uartdll >> 8);
	__builtin_bfin_ssync();
        *pUART_LCR = WLS(8);
	__builtin_bfin_ssync();

	asm("sti r6;"
	"r6 = [sp++];");	
}

/*********************************************************************************/

/* Read the PLL_STAT register */
unsigned long get_pll_status(void)	{
	return(*pPLL_STAT);
}

/* Change the core clock - PLL_DIV register */
unsigned long change_core_clock(unsigned long clock)	{
	int tempcsel,csel,ret;
	unsigned long vco;

	clock = clock * MHZ;
	vco = get_vco();
	tempcsel = vco/clock;

	if(tempcsel == 1)	csel = 0;
	else if(tempcsel == 2)	csel = 1;
	else if(tempcsel == 4)	csel = 2;
	else if(tempcsel == 8)	csel = 3;
	else {
#if DPMC_DEBUG
		printk("Wrong core clock selection \n");
		printk("Selecting clock to be same as VCO \n");
#endif
		csel = 0;
	}
	ret = set_pll_div(csel,FLAG_CSEL);
#if DPMC_DEBUG
		if(ret < 0)
			printk("Wrong core clock selection \n");
#endif
	return(get_cclk());
}

/* Returns VCO in Hz */
int get_vco(void)	{
	return((CONFIG_CLKIN_HZ) * ((*(volatile unsigned short *)PLL_CTL >> 9)& 0x3F));
}

/* Sets the PLL_DIV register CSEL or SSEL bits depending on flag */
int set_pll_div(unsigned short sel,unsigned char flag)
{
	if(flag == FLAG_CSEL)	{
		if(sel <= 3)	{
			*pPLL_DIV = ((*pPLL_DIV & 0xCF) | (sel << 4));
			__builtin_bfin_ssync();
			return 0;
		}
		else	{
#if DPMC_DEBUG
			printk("CCLK value selected not valid \n");
#endif
			return -1;	
		}
	}
	else if(flag == FLAG_SSEL)	{
		if(sel < 16)	{
			*pPLL_DIV = (*pPLL_DIV & 0xF0) | sel;
			__builtin_bfin_ssync();
			return 0;
		}
		else	{
#if DPMC_DEBUG
			printk(" SCLK value selected not valid \n");
#endif
			return -1;
		}
	}
	return -1;	
}

unsigned long change_frequency(unsigned long vco_mhz)	{
#if 0
	unsigned long sdrrcval,modeval;
#endif
	unsigned long vco_hz = vco_mhz * MHZ,vl;
	int msel;

	msel = calc_msel(vco_hz);
	msel = (msel << 9);

/* Enable the PLL Wakeup bit in SIC IWR */
	*pSIC_IWR = IWR_ENABLE(0);
	 __builtin_bfin_ssync();

	*pPLL_LOCKCNT = 0x300;
	 __builtin_bfin_ssync();
	
	 __builtin_bfin_ssync();
	*pEBIU_SDGCTL = (*pEBIU_SDGCTL | SRFS);
	 __builtin_bfin_ssync();
	
	vl = *pPLL_CTL;
	asm("ssync");
	vl &= 0x81FF;
	msel |= vl;

	*pPLL_CTL = msel;
	 __builtin_bfin_ssync();

	asm("[--SP] = R6;"
	    "CLI R6;");
	__builtin_bfin_ssync();
	asm("IDLE;"
	"STI R6;"
	"R6 = [SP++];");

	while(!(*pPLL_STAT & PLL_LOCKED));

	*pEBIU_SDRRC = get_sdrrcval((get_sclk()));
	 __builtin_bfin_ssync();

	*pEBIU_SDGCTL = *pEBIU_SDGCTL & ~SRFS;
	 __builtin_bfin_ssync();

#if 0
	*pEBIU_SDGCTL =	(SCTLE | CL_2 | SDRAM_tRAS1 | SDRAM_tRP1 | SDRAM_tRCD1 | SDRAM_tWR1);
	 __builtin_bfin_ssync();
#endif

#if 0
	/* May not be required */
	if(*pEBIU_SDSTAT & SDRS) {

		*pEBIU_SDRRC = get_sdrrcval((get_sclk()*MHZ));
		 __builtin_bfin_ssync();

		*pEBIU_SDBCTL = 0x13;
		 __builtin_bfin_ssync();

		modeval = (SCTLE | CL_2 | SDRAM_tRAS1 | SDRAM_tRP1 | SDRAM_tRCD1 | SDRAM_tWR1 | PSS);
		*pEBIU_SDGCTL = modeval;
		 __builtin_bfin_ssync();
	}
#endif
	return(get_vco());
}

int calc_msel(int vco_hz)	{
   	if(vco_hz%(CONFIG_CLKIN_HZ))
                return(vco_hz/(CONFIG_CLKIN_HZ) + 1);
        else
                return(vco_hz/(CONFIG_CLKIN_HZ));

}

void fullon_mode(void)	{

	*pSIC_IWR = IWR_ENABLE(0);
	 __builtin_bfin_ssync();

	*pPLL_LOCKCNT = 0x300;
	 __builtin_bfin_ssync();
	
	 __builtin_bfin_ssync();
	*pEBIU_SDGCTL = *pEBIU_SDGCTL | SRFS;
	 __builtin_bfin_ssync();

/* Together if done, some issues with code generation,so split this way*/
	*pPLL_CTL &= (unsigned short)~(BYPASS);
	*pPLL_CTL &= (unsigned short)~(PDWN);
	*pPLL_CTL &= (unsigned short)~(STOPCK_OFF);
	*pPLL_CTL &= (unsigned short)~(PLL_OFF);
	 __builtin_bfin_ssync();

	asm("[--SP] = R6;"
	    "CLI R6;");
	__builtin_bfin_ssync();
	asm("IDLE;"
	"STI R6;"
	"R6 = [SP++];");

	while((*pPLL_STAT & PLL_LOCKED) != PLL_LOCKED);

	*pEBIU_SDRRC = get_sdrrcval(get_sclk());
	 __builtin_bfin_ssync();

	*pEBIU_SDGCTL = *pEBIU_SDGCTL & ~SRFS;
	 __builtin_bfin_ssync();
}

void active_mode(void)	{

	*pSIC_IWR = IWR_ENABLE(0);
	 __builtin_bfin_ssync();

	*pPLL_LOCKCNT = 0x300;
	 __builtin_bfin_ssync();
	
	 __builtin_bfin_ssync();
	*pEBIU_SDGCTL = *pEBIU_SDGCTL | SRFS;
	 __builtin_bfin_ssync();
	
	*pPLL_CTL = *pPLL_CTL | BYPASS;
	 __builtin_bfin_ssync();

	asm("[--SP] = R6;"
	    "CLI R6;");
	__builtin_bfin_ssync();
	asm("IDLE;"
	"STI R6;"
	"R6 = [SP++];");

	while((*pPLL_STAT & PLL_LOCKED) != PLL_LOCKED);

	*pEBIU_SDRRC = get_sdrrcval(get_sclk());
	 __builtin_bfin_ssync();

	*pEBIU_SDGCTL = *pEBIU_SDGCTL & ~SRFS;
	 __builtin_bfin_ssync();
}

/********************************CHANGE OF VOLTAGE*******************************************/
#if 1

/* 0011 .70 volts
0100 .75 volts
0101 .80 volts
0110 .85 volts
0111 .90 volts
1000 .95 volts
1001 1.00 volts
1010 1.05 volts
1011 1.10 volts
1100 1.15 volts
1101 1.20 volts
*/

/* Calculates the VLEV value for VR_CTL programming*/
unsigned long calc_volt()	{
	int base = 850;
	int val = ((*pVR_CTL >> 4) & 0xF);

	if(val == 6)	return base;

#ifdef DPMC_DEBUG
	printk("returning %u \n",(((val - 6) * 50) + base));
#endif
	return (((val - 6) * 50) + base);
}

/* Change the voltage of the processor */
unsigned long change_voltage(unsigned long volt)	{

	unsigned long vlt,val;
	vlt = calc_vlev(volt);
	val = (*pVR_CTL & 0xFF0F);
	val = (val | (vlt << 4));
	*pVR_CTL = val;
	 __builtin_bfin_ssync();
	asm("[--SP] = R6;"
	    "CLI R6;");
	__builtin_bfin_ssync();
	asm("IDLE;"
	"STI R6;"
	"R6 = [SP++];");
	while(!(get_pll_status() & VOLTAGE_REGULATED));
	return(calc_volt());
}

/* Calculates the voltage at which the processor is running */
int calc_vlev(int vlt)	{

	int base = 6;

	if(vlt == 850)	return base;
	return(((vlt - 850)/50) + base);
}

#endif

/*
 *  We enforce only one user at a time here with the open/close.
 *  Also clear the previous interrupt data on an open, and clean
 *  up things on a close.
 */

/* We use dpmc_lock to protect against concurrent opens.*/
static int dpmc_open(struct inode *inode, struct file *file)
{
	//printk("DPMC Device Opening");
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
    release:     dpmc_release
};

static struct miscdevice dpmc_dev=
{
    DPMC_MINOR,
    "dpmc",
    &dpmc_fops
};

/* Init function called first time */
int __init dpmc_init(void)
{
    printk("blackfin_dpmc_init\n");

    misc_register(&dpmc_dev);
    create_proc_read_entry ("driver/dpmc", 0, 0, dpmc_read_proc, NULL);

    printk("Dynamic Power Management Controller: major=%d, minor = %d\n",MISC_MAJOR, DPMC_MINOR);
    printk(KERN_INFO "DPMC Driver v" DPMC_VERSION "\n");
    return 0;
}

void __exit dpmc_exit (void)
{
    remove_proc_entry ("driver/dpmc", NULL);
    misc_deregister(&dpmc_dev);
}

module_init(dpmc_init);
module_exit(dpmc_exit);

/*
 *  Info exported via "/proc/driver/dpmc".
 */

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

