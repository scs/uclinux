/*
 * Driver code for blackfin Dynamic Power management Controller.	
 *	 
 * Copyright (C) 2004 LG Soft India. 
 * 
 * This file is subject to the terms and conditions of the GNU General Public
 * License. 
 *
 */
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

#include <asm/board/bf533.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/system.h>

#include <asm/dpmc.h>
#include <asm/board/cdefBF533.h>
#include <asm/delay.h>

#define DPMC_VERSION "0.1"

/*static unsigned long dpmc_status = 0;*/

/*static void set_rtc_irq(unsigned char);*/
static loff_t dpmc_llseek(struct file *file, loff_t offset, int origin);
static ssize_t dpmc_read(struct file *file, char *buf,
            size_t count, loff_t *ppos);
static int dpmc_ioctl(struct inode *inode, struct file *file,
             unsigned int cmd, unsigned long arg);
static int dpmc_read_proc(char *page, char **start, off_t off,
                         int count, int *eof, void *data);
unsigned char Set_RTC_Alarm(unsigned int Days, unsigned int Hours, unsigned int Minutes, 
             unsigned int Seconds);

#define DPMC_IS_OPEN         0x01    /* means /dev/dpmc is in use */

/*
 *  Now all the various file operations that we export.
 */

static loff_t dpmc_llseek(struct file *file, loff_t offset, int origin)
{
    return -ESPIPE;
}

static ssize_t dpmc_read(struct file *file, char *buf,
            size_t count, loff_t *ppos)
{
	return -1;
}

static int dpmc_ioctl(struct inode *inode, struct file *file, unsigned int cmd,
             unsigned long arg)
{
	unsigned long cclk_mhz=0,sclk_mhz=0,vco_mhz=0,pll_stat=0;
	double mvolt;

	switch (cmd) {

		case IOCTL_FULL_ON_MODE:
			/*printk("In ioclt acive mode \n");*/
			asm("[--sp] = r5;");
			asm("cli r5;");
			transit_to_newmode(FULLON_MODE);
			change_baud(57600);
			/*printk("Done !!!!!\n");*/
			asm("sti r5;");
			asm("r5 = [sp++];");
		break;				

		case IOCTL_ACTIVE_MODE:
			/*printk("In ioclt acive mode \n");*/
			asm("[--sp] = r5;");
			asm("cli r5;");
			transit_to_newmode(ACTIVE_PLLENABLED);
			change_baud(57600);
			/*printk("Done !!!!!\n");*/
			asm("sti r5;");
			asm("r5 = [sp++];");
		break;
		case IOCTL_SLEEP_MODE:
			/*printk("In ioclt acive mode \n");*/
			asm("[--sp] = r5;");
			asm("cli r5;");
			transit_to_newmode(SLEEP_MODE);
			change_baud(57600);
			/*printk("Done !!!!!\n");*/
			asm("sti r5;");
			asm("r5 = [sp++];");
		break;				

		case IOCTL_DEEP_SLEEP_MODE:
			/*printk("In ioclt acive mode \n");*/
			asm("[--sp] = r5;");
			asm("cli r5;");
			transit_to_newmode(DEEP_SLEEP_MODE);
			change_baud(57600);
			/*printk("Done !!!!!\n");*/
			asm("sti r5;");
			asm("r5 = [sp++];");
		break;				

		case IOCTL_HIBERNATE_MODE:
			transit_to_newmode(HIBERNATE_MODE);
		break;				

		case IOCTL_CHANGE_FREQUENCY:
			copy_from_user(&vco_mhz,(unsigned long *)arg,sizeof(unsigned long));
			/*printk("arg received is %u\n",arg);
			printk("vco_mhz received is %u\n",vco_mhz);*/
			asm("[--sp] = r5;");
			asm("cli r5;");
			/*printk("vco_mhz passing to %u\n",vco_mhz);*/
			vco_mhz = change_frequency(vco_mhz);
			change_core_clock(vco_mhz/1000000);
			/* change_system_clock(vco_mhz/5); */
			change_baud(57600);
	    		copy_to_user((unsigned long *)arg, &vco_mhz, sizeof(unsigned long));
			/*printk("Done !!!!!\n");*/
			asm("sti r5;");
			asm("r5 = [sp++];");
		break;

		case IOCTL_CHANGE_VOLTAGE:
			copy_from_user(&mvolt,(double *)arg,sizeof(double));
			change_voltage(mvolt);
    			copy_to_user((double *)arg, &vco_mhz, sizeof(double));
		break;

		case IOCTL_SET_CCLK:
			copy_from_user(&cclk_mhz,(unsigned long *)arg,sizeof(unsigned long));
			if((get_vco()/1000000) < cclk_mhz)	return -1;
			if(cclk_mhz < get_sclk())	{
				printk("Sorry, core clock has to be greater than system clock\n");
				printk("system clock is %d MHz\n",(int)get_sclk());
				return -1;
			}
			asm("[--sp] = r5;");
			asm("cli r5;");
			/*printk("cclk_mhz passing to %u\n",cclk_mhz);*/
			cclk_mhz = change_core_clock(cclk_mhz);
			printk("cclk_mhz = %u MHz \n",(unsigned int)cclk_mhz);
			change_baud(57600);
	    		copy_to_user((unsigned long *)arg, &cclk_mhz, sizeof(unsigned long));
			/*printk("Done !!!!!\n");*/
			asm("sti r5;");
			asm("r5 = [sp++];");
		break;	

		case IOCTL_SET_SCLK:
			copy_from_user(&sclk_mhz,(unsigned long *)arg,sizeof(unsigned long));
			if((get_vco()/1000000) < sclk_mhz)	return -1;
			if(sclk_mhz > get_cclk())	return -1;
			asm("[--sp] = r5;");
			asm("cli r5;");
			/*printk("sclk_mhz passing to %u\n",sclk_mhz);*/
			sclk_mhz = change_system_clock(sclk_mhz);
			printk("sclk_mhz = %u MHz \n",(unsigned int)sclk_mhz);
			change_baud(57600);
	    		copy_to_user((unsigned long *)arg, &sclk_mhz, sizeof(unsigned long));
			/*printk("Done !!!!!\n");*/
			asm("sti r5;");
			asm("r5 = [sp++];");
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
			printk("vco_mhz = %u\n",(unsigned int)vco_mhz);
    			copy_to_user((unsigned long *)arg, &vco_mhz, sizeof(unsigned long));
			/*printk("arg = %u\n",arg);*/
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
        *pUART_DLL = uartdll & 0xFF;
        *pUART_DLH = uartdll >> 8;
        *pUART_LCR = 0x03;
        asm("ssync;");
}

/*
void change_baud(int baud)	{

	UART_LCR(0) = 0x80;
	UART_DLL(0) = 0x80;
	UART_DLH(0) = 0x0;
	UART_LCR(0) = 0x03;	
	asm("ssync;");
}
*/

/*
 *  We enforce only one user at a time here with the open/close.
 *  Also clear the previous interrupt data on an open, and clean
 *  up things on a close.
 */

/* We use dpmc_lock to protect against concurrent opens.*/
static int dpmc_open(struct inode *inode, struct file *file)
{
	printk("DPMC Device Opening");
/*	if(dpmc_status & DPMC_IS_OPEN)
        	goto busy;
	dpmc_status |= DPMC_IS_OPEN;
*/
	return 0;
/*busy:
	return -EBUSY;*/
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
    misc_register(&dpmc_dev);
    create_proc_read_entry ("driver/dpmc", 0, 0, dpmc_read_proc, NULL);

    printk(KERNEL_INFO "Dynamic Power Management Controller Version %d\n",DPMC_VERSION);
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
 

static int dpmc_proc_output (char *buf)
{
	return 0;
}
*/
static int dpmc_read_proc(char *page, char **start, off_t off,
                         int count, int *eof, void *data)
{
	return -1;

}


/*********************************************************************************/

#define FLAG_CSEL	0x0
#define FLAG_SSEL	0x1

unsigned long get_pll_status(void)	{
	return(*pPLL_STAT);
}

unsigned long change_core_clock(unsigned long clock)	{
	int tempcsel,csel;
	unsigned long vco;

	printk("In change core clock clock = %d\n",(int)clock);
	clock = clock * 1000000;
	vco = get_vco();
	tempcsel = vco/clock;
	if(tempcsel == 1)	csel = 0;
	else if(tempcsel == 2)	csel = 1;
	else if(tempcsel == 4)	csel = 2;
	else if(tempcsel == 8)	csel = 3;
	else	{
		printk("Wrong core clock selection \n");
		printk("Selecting clock to be same as VCO \n");
		csel = 0;
	}
	printk("csel = %d\n",csel);
	if(set_pll_div(csel,FLAG_CSEL) < 0)
		printk("Wrong core clock selection \n");
	return(get_cclk());
}

unsigned long change_system_clock(unsigned long clock)	{
	int ssel;
	unsigned long vco;
	
	printk("In change system clock = %d\n",(int)clock);
	clock = clock * 1000000;
	vco = get_vco();
	ssel = vco/clock;
	printk("ssel = %d\n",ssel);
	if(set_pll_div(ssel,FLAG_SSEL) < 0)
		printk("Wrong system clock selection \n");
	return(get_sclk());
}

int get_vco(void)	{
	return((CONFIG_CLKIN * 1000000) * ((*pPLL_CTL >> 9)& 0x3F));
}

int set_pll_div(unsigned short sel,unsigned char flag)
{

	if(flag == FLAG_CSEL)	{
		if(sel <= 3)	{
			asm("csync;");
			*pPLL_DIV = ((*pPLL_DIV & 0xCF) | (sel << 4));
			asm("csync;");
			return 0;
		}
		else	{
			printk(" CCLK value selected not valid \n");
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
			printk(" SCLK value selected not valid \n");
			return -1;
		}
	}
	return -1;	
}

unsigned long change_frequency(unsigned long vco_mhz)	{
	unsigned long vco_hz = vco_mhz * 1000000;
	int msel;
	
	printk("vco_hz = %u\n",(unsigned int)vco_hz);
#if 0
	unmask_wdog_wakeup_evt();
	program_wdog_timer();
	pll_bypass_on();
	pll_seq_trans();
	clear_wdog_wakeup_evt();
	msel = calc_msel(vco_hz);	
	set_pll_ctl(msel); 	/* we are assuming DF is always 0 */	
	pll_bypass_off();
	program_wdog_timer();	/*Reloading wdog counter, currently FIXME */
	pll_seq_trans();	
	clear_wdog_wakeup_evt();	/* FIXME, disabling the wdog timer??? */
#endif

	msel = calc_msel(vco_hz);
	printk("msel = %d \t vco_hz = %u\n",(int)msel,(unsigned int)vco_hz);
	*pPLL_CTL = (msel << 9);
	transition();
		
	return(get_vco());
}
	
int calc_msel(int vco_hz)	{
	printk("CONFIG_CLKIN = %d\n",CONFIG_CLKIN);
	return(vco_hz/(CONFIG_CLKIN * 1000000));
}

void transition(void)
{
	int i;
	for(i=0;i<10000;i++);
	for(i=0;i<10000;i++);
	for(i=0;i<10000;i++);
}
		
double change_voltage(double volt)	{
#if 0
	volatile unsigned long pll_stat,vlt;
	vlt = vlt * 100000;	/* just to avoid floating point */
	vlt = calc_vlev(vlt);
	set_vr_ctl(vlt);
	pll_stat = get_pll_status();
	while(!(pll_stat >> 7));
	return(calc_volt()/100000);
#endif
	return 0;
}

int calc_vlev(int vlt)	{

	int base = 3;

	if(vlt == 70)	return base;
	return(((vlt - 70)/5) + base);
}

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

int calc_volt()	{
	int base = 70;			
	int val = ((*pVR_CTL >> 4) & 0xF);

	if(val == 3)	return base;
	return (((val - 3) * 5) + base);
}

extern void transit_sleep_mode(void);

int transit_to_newmode (int newmode)	{

	int current_mode=0;

	int stat = get_pll_status();
	if(stat & 0x10)		current_mode = SLEEP_MODE;
	else if(stat & 0x08)	current_mode = DEEP_SLEEP_MODE;
	else if(stat & 0x04)	current_mode = ACTIVE_PLLDISABLED;
	else if(stat & 0x02)	current_mode = FULLON_MODE;
	else if(stat & 0x01)	current_mode = ACTIVE_PLLENABLED;

	printk("stat = %d\n",stat);
	printk("current mode = %d\n",current_mode);

	if(current_mode == newmode)	{
		printk("Operating mode change not required \n");
		return 0;
	}
	
	/* unmask_wdog_wakeup_evt();
	program_wdog_timer(); */
	
	switch(current_mode)	{
		case FULLON_MODE:
			switch(newmode)	{
				case ACTIVE_PLLENABLED:
					asm("[--SP] = ( R7:4, P5:5);"
                                        "p0.h = 0xffc0;"
                                        "p0.l = 0x0000;"
                                        "r7 = w[p0](z);"
					"bitset(r7,8);"
					"w[p0] = r7;"
					"ssync;"
					
					"cli r7;"
					"idle;"
					"ssync;"
					"sti r7;"
					"( R7:4, P5:5) = [SP++];");
				break;
				case SLEEP_MODE:
					/*asm("[--SP] = ( R7:4, P5:5);"
					"cli r7;"
					"p0.h = 0xffc0;"
                                        "p0.l = 0x0000;"
                                        "r7 = w[p0](z);"
					"bitset(r7,6);"
					"bitclr(r7,5);"
					"bitset(r7,3);"
					"w[p0] = r7;"
					"ssync;"
					"sti r7;"					
					"cli r7;"
					"idle;"
					"ssync;"
					"sti r7;"
					"( R7:4, P5:5) = [SP++];");*/
					/*transit_sleep_mode();
					Set_RTC_Alarm(0,0,2,10);	
					printk("value of pll = 0x%x\n",get_pll_status());*/
				break;
				case DEEP_SLEEP_MODE:
					/*Set_RTC_Alarm(0,0,2,10);	
					asm("[--SP] = ( R7:4, P5:5);"
					"p0.h = 0xffc0;"
                                        "p0.l = 0x0000;"
                                        "r7 = w[p0](z);"
					"bitset(r7,8);"
					"bitset(r7,5);"
					"bitset(r7,3);"
					"bitset(r7,1);"
					"bitclr(r7,7);"
					"bitclr(r7,6);"
					"w[p0] = r7;"
					"ssync;"
					
					"cli r7;"
					"idle;"
					"ssync;"
					"sti r7;"
					"( R7:4, P5:5) = [SP++];");*/
				break;
			}
		break;
		case ACTIVE_PLLENABLED:
			switch(newmode)	{
				case SLEEP_MODE:
					/*
					set_clr_stopck(OFF);
					set_clr_pdwn(ON);
					*/
				break;				
				case DEEP_SLEEP_MODE:
					/*set_clr_pdwn(OFF);*/					
				break;				
				case FULLON_MODE:
					asm("[--SP] = ( R7:4, P5:5);"
					"p0.h = 0xffc0;"
					"p0.l = 0x0000;"
					"r7 = w[p0](z);"
					"bitclr(r7,8);"
					"w[p0] = r7;"	

					"cli r7;"
					"idle;"
					"ssync;"
					"sti r7;"
					"( R7:4, P5:5) = [SP++];");

					/*pll_bypass_off();
					set_clr_plloff(ON);
					set_clr_stopck(OFF);
					set_clr_pdwn(OFF);					
					transition();*/
				break;					
			}
		break;
		case SLEEP_MODE:
			switch(newmode)	{
				case FULLON_MODE:
					asm("[--SP] = ( R7:4, P5:5);"
					"p0.h = 0xffc0;"
					"p0.l = 0x0000;"
					"r7 = w[p0](z);"
					"bitclr(r7,3);"
					"w[p0] = r7;"	

					"cli r7;"
					"idle;"
					"ssync;"
					"sti r7;"
					"( R7:4, P5:5) = [SP++];");

					//SIC_IWR |= 0x1; //Set the PLLWAKEUP in SIC_IWR
					//pll_bypass_off();
				break;					
				case ACTIVE_PLLENABLED:
					*pSIC_IWR |= 0x1;
					pll_bypass_on();
				break;
			}
		break;
		case DEEP_SLEEP_MODE:
		/* Program the RTC to get an interrupt */
        		/*set_rtc_irq(STPW_INT_EN);							
			*(volatile unsigned long *)RTC_SWCNT = 255;
			*/
			break;

		case HIBERNATE_MODE:
			break;
				
	}
	/* pll_seq_trans();
	clear_wdog_wakeup_evt(); */
	return 0;
}

#if 0	
static void set_rtc_irq(unsigned char bit)
{
	unsigned char val;

	val = *(volatile unsigned short *)RTC_ICTL;
	val |= bit;
	*(volatile unsigned short *)RTC_ICTL = val;
	
	while(!(*(volatile unsigned short *)RTC_ISTAT) & 0x8000) {
		/*Delay issues -- BFin*/
		asm("ssync;")
	        /*schedule();*/
    	}
    	*(volatile unsigned short *)RTC_ISTAT = 0x8000;	
}
#endif

unsigned char Set_RTC_Alarm(unsigned int Days, unsigned int Hours, unsigned int Minutes, 
             unsigned int Seconds)
{
#if 0
	int i;
	if ((Days < 32767) && (Hours < 24) && (Minutes < 60) && (Seconds < 60))
	{
		unsigned int Alarm = 0;
		*(volatile unsigned short *)RTCISTAT_ADDR = 0x3FFF;
		asm("ssync;");
		for(i=0;i<10000;i++);
		Alarm |= ((Days &= 0xBFFF) <<  17);
		Alarm |= ((Hours &= 0x1F) <<  12);
		Alarm |= ((Minutes &= 0x3F) << 6);
		Alarm |= (Seconds &= 0x3F);
		RTCALARM = Alarm;
		asm("ssync;");
		while (!(0x4000 & *(volatile unsigned short *)RTCISTAT_ADDR))
		{
		}
		return 0;
	}
	else
		return 1;	
#endif
	return 0;
}
