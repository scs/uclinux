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

#include <asm/board/cdefBF532.h>
#include <asm/board/defBF532.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <asm/dpmc.h>
#include "blackfin_dpmc.h"
#include <asm/delay.h>

unsigned long SDRAM_tRP1;
unsigned long SDRAM_tRAS1;
unsigned long SDRAM_tRCD1;
unsigned long SDRAM_tWR1;

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
	asm("ssync;");
	*pEBIU_SDGCTL = (*pEBIU_SDGCTL | SRFS);
	asm("ssync;");

	ret = set_pll_div(ssel,FLAG_SSEL);

#if DPMC_DEBUG
	if(ret < 0)
		printk("Wrong system clock selection \n");
#endif

	*pEBIU_SDRRC = get_sdrrcval((get_sclk()*MHZ));
	asm("ssync;");

	/* Get SDRAM out of self refresh mode */
	*pEBIU_SDGCTL = (*pEBIU_SDGCTL & ~SRFS);
	asm("ssync;");

	/* May not be required */
#if 0
	*pEBIU_SDGCTL = (*pEBIU_SDGCTL | SCTLE | CL_2  | SDRAM_tRAS1  | SDRAM_tRP1  | SDRAM_tRCD1  | SDRAM_tWR1);
	asm("ssync;");
#endif
	return(get_sclk());
}

static int dpmc_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
	unsigned long cclk_mhz=0,sclk_mhz=0,vco_mhz=0,pll_stat=0,vco_mhz_bk,mvolt,wdog_tm;
	/* struct bf533_serial *in; */

	switch (cmd) {
		case IOCTL_FULL_ON_MODE:
			fullon_mode();
			change_baud(CONSOLE_BAUD_RATE);
		break;

		case IOCTL_ACTIVE_MODE:
			active_mode();
			change_baud(CONSOLE_BAUD_RATE);
		break;
		case IOCTL_SLEEP_MODE:
			sleep_mode();
		break;				

		case IOCTL_DEEP_SLEEP_MODE:
			deep_sleep();
		break;
		
		case IOCTL_HIBERNATE_MODE:
			hibernate_mode();
		break;

		case IOCTL_CHANGE_FREQUENCY:
			if(!(get_pll_status() & 0x2))	return -1;
			copy_from_user(&vco_mhz,(unsigned long *)arg,sizeof(unsigned long));
			vco_mhz_bk = vco_mhz;
			if((vco_mhz > MAX_VCO) || (vco_mhz < MIN_VCO))	return -1;
			/* This is done to avoid drastic change of frequency since it affects SSEL.
			 * At 135MHz keeping SSEL as 5 or 1 does not matter 
			 */
			if(vco_mhz > INTER_FREQ) {
				vco_mhz = change_frequency(INTER_FREQ);
				change_core_clock(vco_mhz/MHZ);
				if((vco_mhz/(DEF_SSEL * MHZ)) < MIN_SCLK) {
#if DPMC_DEBUG
					printk("System clock being changed to minimum \n");
#endif
					sclk_mhz = change_sclk((MIN_SCLK));
				}
				else
					sclk_mhz = change_sclk((vco_mhz/(DEF_SSEL * MHZ)));
				change_baud(CONSOLE_BAUD_RATE);

				vco_mhz = change_frequency(vco_mhz_bk);
				change_core_clock(vco_mhz/MHZ);
				if((vco_mhz/(DEF_SSEL * MHZ)) < MIN_SCLK) {
#if DPMC_DEBUG
					printk("System clock being changed to minimum \n");
#endif
					sclk_mhz = change_sclk((MIN_SCLK));
				}
				else
					sclk_mhz = change_sclk((vco_mhz/(DEF_SSEL * MHZ)));
				change_baud(CONSOLE_BAUD_RATE);
			}
			else {
				vco_mhz = change_frequency(vco_mhz_bk);
				change_core_clock(vco_mhz/MHZ);
				if((vco_mhz/(DEF_SSEL * MHZ)) < MIN_SCLK) {
#if DPMC_DEBUG
					printk("System clock being changed to minimum \n");
#endif
					sclk_mhz = change_sclk(MIN_SCLK);
					
				}
				else
					sclk_mhz = change_sclk((vco_mhz/5000000));
				change_baud(CONSOLE_BAUD_RATE);
			}
			vco_mhz = vco_mhz/MHZ;
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
			copy_from_user(&cclk_mhz,(unsigned long *)arg,sizeof(unsigned long));
			if((get_vco()/MHZ) < cclk_mhz)	return -1;
			if(cclk_mhz <= get_sclk()) {
#if DPMC_DEBUG
				printk("Sorry, core clock has to be greater than system clock\n");
				printk("Current System Clock is %u MHz\n",get_sclk());
#endif
				return -1;
			}
			cclk_mhz = change_core_clock(cclk_mhz);
	    		copy_to_user((unsigned long *)arg, &cclk_mhz, sizeof(unsigned long));
		break;

		case IOCTL_SET_SCLK:
			copy_from_user(&sclk_mhz,(unsigned long *)arg,sizeof(unsigned long));
			if((get_vco()/MHZ) < sclk_mhz)	return -1;
			if(sclk_mhz >= get_cclk())		return -1;
			if(sclk_mhz > MAX_SCLK)			return -1;
			if(sclk_mhz < MIN_SCLK)			return -1;
			sclk_mhz = change_sclk(sclk_mhz);
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
			vco_mhz = get_vco()/MHZ;
    			copy_to_user((unsigned long *)arg, &vco_mhz, sizeof(unsigned long));
		break;
		
		case IOCTL_DISABLE_WDOG_TIMER:
			disable_wdog_timer();
		break;
		
		case IOCTL_UNMASK_WDOG_WAKEUP_EVENT:
			unmask_wdog_wakeup_evt();
		break;
		
		case IOCTL_PROGRAM_WDOG_TIMER:
			copy_from_user(&wdog_tm,(unsigned long *)arg,sizeof(unsigned long));
			program_wdog_timer(wdog_tm);
		break;

		case IOCTL_CLEAR_WDOG_WAKEUP_EVENT:
			clear_wdog_wakeup_evt();
		break;				
	}
	return 0;	
}

void change_baud(int baud)      {
        int uartdll,sclk;
	/* If in active mode sclk and cclk run at CCLKIN*/
	if(get_pll_status() & 0x1)	{
		sclk = CONFIG_CLKIN;
	}
	else	{
       		sclk = get_sclk();
	}
        uartdll = (sclk*MHZ)/(16*baud);
        *pUART_LCR = DLAB;
        asm("ssync;");
        *pUART_DLL = (uartdll & 0xFF);
        asm("ssync;");
        *pUART_DLH = (uartdll >> 8);
        asm("ssync;");
        *pUART_LCR = WLS(8);
        asm("ssync;");
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
	return((CONFIG_CLKIN * MHZ) * ((*(volatile unsigned short *)PLL_CTL >> 9)& 0x3F));
}

/* Sets the PLL_DIV register CSEL or SSEL bits depending on flag */
int set_pll_div(unsigned short sel,unsigned char flag)
{
	if(flag == FLAG_CSEL)	{
		if(sel <= 3)	{
			*pPLL_DIV = ((*pPLL_DIV & 0xCF) | (sel << 4));
			asm("ssync;");
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
			asm("ssync;");
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
	unsigned long vco_hz = vco_mhz * MHZ;
	int msel;

	msel = calc_msel(vco_hz);
	msel = (msel << 9);

/* Enable the PLL Wakeup bit in SIC IWR */
	*pSIC_IWR = (*pSIC_IWR | IWR_ENABLE(0));
	asm("ssync;");

#if 0
	*pWDOG_CTL = 0xAD6;
	asm("ssync;");

	*pWDOG_CNT = 0x100000;
	asm("ssync;");

	*pWDOG_STAT = 0x0;
	asm("ssync;");

	*pWDOG_CTL = 0xAA4;
	asm("ssync;");
#endif

	*pPLL_LOCKCNT = 0x300;
	asm("ssync;");
	
	asm("ssync;");
	*pEBIU_SDGCTL = (*pEBIU_SDGCTL | SRFS);
	asm("ssync;");
	
	*pPLL_CTL = msel;
	asm("ssync;");

	asm("[--SP] = R6;"
	"CLI R6;"
	"SSYNC;"
	"IDLE;"
	"STI R6;"
	"R6 = [SP++];");

	while(!(*pPLL_STAT & PLL_LOCKED));

	*pEBIU_SDRRC = get_sdrrcval((get_sclk()*MHZ));
	asm("ssync;");

	*pEBIU_SDGCTL = *pEBIU_SDGCTL & ~SRFS;
	asm("ssync;");

#if 0
	*pEBIU_SDGCTL =	(SCTLE | CL_2 | SDRAM_tRAS1 | SDRAM_tRP1 | SDRAM_tRCD1 | SDRAM_tWR1);
	asm("ssync;");
#endif

#if 0
	/* May not be required */
	if(*pEBIU_SDSTAT & SDRS) {

		*pEBIU_SDRRC = get_sdrrcval((get_sclk()*MHZ));
		asm("ssync;");

		*pEBIU_SDBCTL = 0x13;
		asm("ssync;");

		modeval = (SCTLE | CL_2 | SDRAM_tRAS1 | SDRAM_tRP1 | SDRAM_tRCD1 | SDRAM_tWR1 | PSS);
		*pEBIU_SDGCTL = modeval;
		asm("ssync;");
	}
#endif

#if 0
	*pWDOG_CTL = 0x8006;
	asm("ssync;");
#endif
	return(get_vco());
}

int calc_msel(int vco_hz)	{
	return(vco_hz/(CONFIG_CLKIN * MHZ));
}

void fullon_mode(void)	{

	*pSIC_IMASK = (*pSIC_IMASK | SIC_MASK(0));
	asm("ssync;");

	*pSIC_IWR = (*pSIC_IWR | IWR_ENABLE(0));
	asm("ssync;");

	*pPLL_LOCKCNT = 0x300;
	asm("ssync;");
	
	asm("ssync;");
	*pEBIU_SDGCTL = *pEBIU_SDGCTL | SRFS;
	asm("ssync;");
	
	//*pPLL_CTL &= 0xFED7;
	*pPLL_CTL &= (~BYPASS | ~PDWN | ~STOPCK_OFF | ~PLL_OFF);
	asm("ssync;");

	asm("[--SP] = R6;"
	"CLI R6;"
	"SSYNC;"
	"IDLE;"
	"STI R6;"
	"R6 = [SP++];");

	while((*pPLL_STAT & PLL_LOCKED) != PLL_LOCKED);

	*pEBIU_SDRRC = get_sdrrcval((get_sclk()*MHZ));
	asm("ssync;");

	*pEBIU_SDGCTL = *pEBIU_SDGCTL & ~SRFS;
	asm("ssync;");
}

void active_mode(void)	{

	*pSIC_IMASK |= SIC_MASK(0);
	asm("ssync;");

	*pIMASK |= 0x80;
	asm("csync;");

	*pSIC_IWR |= IWR_ENABLE(0);
	asm("ssync;");

	*pPLL_LOCKCNT = 0x300;
	asm("ssync;");
	
	asm("ssync;");
	*pEBIU_SDGCTL = *pEBIU_SDGCTL | SRFS;
	asm("ssync;");
	
	*pPLL_CTL |= BYPASS;
	asm("ssync;");

	asm("[--SP] = R6;"
	"CLI R6;"
	"SSYNC;"
	"IDLE;"
	"STI R6;"
	"R6 = [SP++];");

	while((*pPLL_STAT & PLL_LOCKED) != PLL_LOCKED);

	*pEBIU_SDRRC = get_sdrrcval((get_sclk()*MHZ));
	asm("ssync;");

	*pEBIU_SDGCTL = *pEBIU_SDGCTL & ~SRFS;
	asm("ssync;");
}

void enable_wakes() {
	
	*pSIC_IWR |= IWR_ENABLE(7);
	asm("ssync;");	

	*pSIC_IMASK |= SIC_MASK(7);
	asm("ssync;");

	*pIMASK |= EVT_IVG8_P;
	asm("csync;");
}


void clear_rtc_istat(void) {
	*pRTC_ISTAT = (SWEF|AEF|SEF|MEF|HEF|DEF|DAEF|WCOM);
	asm("ssync;");

	/* Just set it, so that we wait for complete */
	*pRTC_ICTL |= PREN;
	asm("ssync;");

	while(!(*pRTC_ISTAT & WCOM));
}

void sleep_mode(void) {
	enable_wakes();
	clear_rtc_istat();

	*pPLL_LOCKCNT = 0x300;
	asm("ssync;");

	*pPLL_CTL |= STOPCK_OFF;
		
	asm("[--SP] = R6;"
	"CLI R6;"
	"SSYNC;"
	"IDLE;"
	"STI R6;"
	"R6 = [SP++];");

	while((*pPLL_STAT & PLL_LOCKED) != PLL_LOCKED);

	*pPLL_CTL &= ~STOPCK_OFF;
	asm("IDLE;");
}

void deep_sleep(void) {
	enable_wakes();
	clear_rtc_istat();

	*pPLL_LOCKCNT = 0x300;
	asm("ssync;");

	*pPLL_CTL |= PDWN;
		
	asm("[--SP] = R6;"
	"CLI R6;"
	"SSYNC;"
	"IDLE;"
	"STI R6;"
	"R6 = [SP++];");

/* actually may not reach here SDRAM contents gets destroyed */
	while((*pPLL_STAT & PLL_LOCKED) != PLL_LOCKED);

	*pPLL_CTL &= ~PDWN;
	asm("IDLE;");
}

void hibernate_mode(void) {
	enable_wakes();
	clear_rtc_istat();

	*pPLL_LOCKCNT = 0x300;
	asm("ssync;");

	*pVR_CTL |= WAKE;
	*pVR_CTL &= ~FREQ_3;
	asm("ssync;");
		
	asm("[--SP] = R6;"
	"CLI R6;"
	"SSYNC;"
	"IDLE;"
	"STI R6;"
	"R6 = [SP++];");

/* actually may not reach here SDRAM contents gets destroyed */
	while((*pPLL_STAT & PLL_LOCKED) != PLL_LOCKED);

	*pVR_CTL &= ~WAKE;
	*pVR_CTL |= FREQ_3;
	asm("IDLE;");
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
	asm("ssync;");
	asm("[--SP] = R6;"
	"CLI R6;"
	"SSYNC;"
	"IDLE;"
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
	printk("DPMC Device Opening");
	return 0;
}

static int dpmc_release(struct inode *inode, struct file *file)
{

    return 0;
}

/*
 *  The various file operations we support.
 */
static struct file_operations dpmc_fops = {
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

static int dpmc_proc_output (char *buf)
{
	return 0;
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


