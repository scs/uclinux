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

#define MAX_VCO		600
#define MIN_VCO		50

#define MAX_SCLK	132
#define MIN_SCLK	27

/* file currently works on ezkit. not completely tested */

unsigned long SDRAM_tRP1;
unsigned long SDRAM_tRAS1;
unsigned long SDRAM_tRCD1;
unsigned long SDRAM_tWR1;

unsigned long get_sdrrcval(unsigned long sc)
{
	unsigned long SCLK = sc;
	unsigned long SDRAM_tRP;
	unsigned long SDRAM_tRAS;
	unsigned long SDRAM_tRCD;
	unsigned long SDRAM_tWR;
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

	SCLK = SCLK/1000000;
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
	int tempssel,ssel,ret;
	unsigned long vco;

	clock = clock * 1000000;
	vco = get_vco();
	ssel = vco/clock;
	
	ssel = get_closest_ssel(ssel,ssel-1,ssel+1,vco,clock);
	if(ssel == 0)	ssel = 1;

	if(ssel > 15) {
		printk("Selecting ssel = 15 \n");
		ssel = 15;
	}
	
	asm("ssync;");
	*pEBIU_SDGCTL = *pEBIU_SDGCTL | 0x01000000;
	asm("ssync;");

	ret = set_pll_div(ssel,FLAG_SSEL);

#if DPMC_DEBUG
	if(ret < 0)
		printk("Wrong system clock selection \n");
#endif

	*pEBIU_SDRRC = get_sdrrcval((get_sclk()*1000000));
	asm("ssync;");

	*pEBIU_SDGCTL = *pEBIU_SDGCTL & 0xFEFFFFFF;
	asm("ssync;");

	*pEBIU_SDGCTL = (*pEBIU_SDGCTL | SCTLE | CL_2  | SDRAM_tRAS1  | SDRAM_tRP1  | SDRAM_tRCD1  | SDRAM_tWR1);
	asm("ssync;");
	
	return(get_sclk());
}

static int dpmc_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
	unsigned long cclk_mhz=0,sclk_mhz=0,vco_mhz=0,pll_stat=0,vco_mhz_bk;
	unsigned long mvolt;
	struct bf533_serial *in;

	switch (cmd) {
		case IOCTL_FULL_ON_MODE:
			fullon_mode();
			change_baud(57600);
		break;

		case IOCTL_ACTIVE_MODE:
			active_mode();
			change_baud(57600);
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
			if(vco_mhz > 135) {
				vco_mhz = change_frequency(135);
				change_core_clock(vco_mhz/1000000);
				if((vco_mhz/5000000) < MIN_SCLK) {
#if DPMC_DEBUG
					printk("System clock being changed to minimum \n");
#endif
					sclk_mhz = change_sclk((MIN_SCLK));
				}
				else
					sclk_mhz = change_sclk((vco_mhz/5000000));
				change_baud(57600);

				vco_mhz = change_frequency(vco_mhz_bk);
				change_core_clock(vco_mhz/1000000);
				if((vco_mhz/5000000) < MIN_SCLK) {
#if DPMC_DEBUG
					printk("System clock being changed to minimum \n");
#endif
					sclk_mhz = change_sclk((MIN_SCLK));
				}
				else
					sclk_mhz = change_sclk((vco_mhz/5000000));
				change_baud(57600);
			}
			else {
				vco_mhz = change_frequency(vco_mhz_bk);
				change_core_clock(vco_mhz/1000000);
				if((vco_mhz/5000000) < MIN_SCLK) {
#if DPMC_DEBUG
					printk("System clock being changed to minimum \n");
#endif
					sclk_mhz = change_sclk((MIN_SCLK));
				}
				else
					sclk_mhz = change_sclk((vco_mhz/5000000));
				change_baud(57600);
			}
			vco_mhz = vco_mhz/1000000;
	    		copy_to_user((unsigned long *)arg, &vco_mhz, sizeof(unsigned long));
		break;

		case IOCTL_CHANGE_VOLTAGE:
			copy_from_user(&mvolt,(unsigned long *)arg,sizeof(unsigned long));
			if((mvolt >= 850) && (mvolt <= 1300) && ((mvolt%50) == 0))
				mvolt = change_voltage(mvolt);
			else {
				printk("Selected voltage not valid \n");
				return -1;
			}
    			copy_to_user((unsigned long *)arg, &mvolt, sizeof(unsigned long));
		break;
		case IOCTL_SET_CCLK:
			copy_from_user(&cclk_mhz,(unsigned long *)arg,sizeof(unsigned long));
			if((get_vco()/1000000) < cclk_mhz)	return -1;
			if(cclk_mhz < get_sclk()) {
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
			if((get_vco()/1000000) < sclk_mhz)	return -1;
			if(sclk_mhz > get_cclk())		return -1;
			if(sclk_mhz > MAX_SCLK)			return -1;
			if(sclk_mhz < MIN_SCLK)			return -1;
			sclk_mhz = change_sclk(sclk_mhz);
			change_baud(57600);
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
			vco_mhz = get_vco()/1000000;
    			copy_to_user((unsigned long *)arg, &vco_mhz, sizeof(unsigned long));
		break;

	}
	return 0;	
}

void change_baud(int baud)      {
        int uartdll,sclk;
	if(get_pll_status() & 0x1)	{
		sclk = CONFIG_CLKIN;
	}
	else	{
       		sclk = get_sclk();
	}
        uartdll = (sclk*1000000)/(16*baud);
        *pUART_LCR = 0x80;
        asm("ssync;");
        *pUART_DLL = uartdll & 0xFF;
        asm("ssync;");
        *pUART_DLH = uartdll >> 8;
        asm("ssync;");
        *pUART_LCR = 0x03;
        asm("ssync;");
}

/*********************************************************************************/

unsigned long get_pll_status(void)	{
	return(*pPLL_STAT);
}

unsigned long change_core_clock(unsigned long clock)	{
	int tempcsel,csel,ret;
	unsigned long vco;

	clock = clock * 1000000;
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

int get_vco(void)	{
	return((CONFIG_CLKIN * 1000000) * ((*(volatile unsigned short *)PLL_CTL >> 9)& 0x3F));
}

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
	unsigned long sdrrcval,modeval;
	unsigned long vco_hz = vco_mhz * 1000000;
	int msel;
	int i;

	msel = calc_msel(vco_hz);
	msel = (msel << 9);

	*pSIC_IWR = (*pSIC_IWR | 0x1);
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
	*pEBIU_SDGCTL = *pEBIU_SDGCTL | 0x01000000;
	asm("ssync;");
	
	*pPLL_CTL = msel;
	asm("ssync;");

	asm("[--SP] = R6;"
	"CLI R6;"
	"SSYNC;"
	"IDLE;"
	"STI R6;"
	"R6 = [SP++];");

	while(!(*pPLL_STAT & 0x20));

	*pEBIU_SDRRC = get_sdrrcval((get_sclk()*1000000));
	asm("ssync;");

	*pEBIU_SDGCTL = *pEBIU_SDGCTL & 0xFEFFFFFF;
	asm("ssync;");

#if 0
	*pEBIU_SDGCTL =	(SCTLE | CL_2 | SDRAM_tRAS1 | SDRAM_tRP1 | SDRAM_tRCD1 | SDRAM_tWR1);
	asm("ssync;");

	if(*pEBIU_SDSTAT & SDRS) {

		*pEBIU_SDRRC = get_sdrrcval((get_sclk()*1000000));
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
	return(vco_hz/(CONFIG_CLKIN * 1000000));
}

/********************************CHANGE OF VOLTAGE*******************************************/
#if 1

/* 0011 .70 volts	returns .70 * 100
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

unsigned long calc_volt()	{
	int base = 850;
	int val = ((*pVR_CTL >> 4) & 0xF);

	if(val == 6)	return base;

	printk("returning %u \n",(((val - 6) * 50) + base));
	return (((val - 6) * 50) + base);
}

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
	while(!(get_pll_status() & 0x80));
	return(calc_volt());
}

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
    release:    dpmc_release,
};

static struct miscdevice dpmc_dev=
{
    DPMC_MINOR,
    "dpmc",
    &dpmc_fops
};


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


