/*
 * arch/bfinommu/asm/dpmc.h -  Miscellaneous IOCTL commands for Dynamic Power
 *   			 	Management Controller Driver.	  
 * Copyright (C) 2004 LG Soft India.
 *
 */
#ifndef _BFINNOMMU_DPMC_H_
#define _BFINNOMMU_DPMC_H_

#define SLEEP_MODE		1
#define DEEP_SLEEP_MODE		2
#define ACTIVE_PLLDISABLED	3
#define FULLON_MODE		4
#define ACTIVE_PLLENABLED	5
#define HIBERNATE_MODE		6

#define IOCTL_FULL_ON_MODE	_IO('s', 0xA0)
#define IOCTL_ACTIVE_MODE	_IO('s', 0xA1)
#define IOCTL_SLEEP_MODE	_IO('s', 0xA2)
#define IOCTL_DEEP_SLEEP_MODE	_IO('s', 0xA3)
#define IOCTL_HIBERNATE_MODE	_IO('s', 0xA4)
#define IOCTL_CHANGE_FREQUENCY	_IOW('s', 0xA5, unsigned long)
#define IOCTL_CHANGE_VOLTAGE	_IOW('s', 0xA6, double)
#define IOCTL_SET_CCLK		_IOW('s', 0xA7, unsigned long)
#define IOCTL_SET_SCLK		_IOW('s', 0xA8, unsigned long)
#define IOCTL_GET_PLLSTATUS	_IOW('s', 0xA9, unsigned long)
#define IOCTL_GET_CORECLOCK	_IOW('s', 0xAA, unsigned long)
#define IOCTL_GET_SYSTEMCLOCK	_IOW('s', 0xAB, unsigned long)
#define IOCTL_GET_VCO		_IOW('s', 0xAC, unsigned long)

#define DPMC_MINOR		254

#define ON	0
#define OFF	1	


int transit_to_newmode (int newmode);
unsigned long calc_volt(void);
int calc_vlev(int vlt);
unsigned long change_voltage(unsigned long volt);
int calc_msel(int vco_hz);
unsigned long change_frequency(unsigned long vco_mhz);
int set_pll_div(unsigned short sel,unsigned char flag);
int get_vco(void);
unsigned long change_system_clock(unsigned long clock);
unsigned long change_core_clock(unsigned long clock);
unsigned long get_pll_status(void);
void change_baud(int baud);      
void transition(void);

extern unsigned long get_cclk(void);
extern unsigned long get_sclk(void);


void pll_seq_trans(void);
void unmask_wdog_wakeup_evt(void);
void program_wdog_timer(void);
void pll_bypass_on(void);
void pll_bypass_off(void);
void clear_wdog_wakeup_evt(void);
void set_pll_ctl(int msel);
void set_vr_ctl(volatile unsigned long);
void set_clr_stopck(int);
void set_clr_pdwn(int);
void set_clr_plloff(int);
void transition(void);

#endif	/*_BFINNOMMU_DPMC_H_*/
