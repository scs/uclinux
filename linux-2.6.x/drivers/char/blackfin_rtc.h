
/*
 * Copyright (C) 2004  LG Soft India 
 */

/* bit define */
#define DAY_BITS_OFF     17
#define HOUR_BITS_OFF    12
#define MIN_BITS_OFF     6
#define SEC_BITS_OFF     0

#define MIN_TO_SECS(_x_) (60 * _x_)
#define HRS_TO_SECS(_x_) (60 * 60 * _x_)
#define DAYS_TO_SECS(_x_) (24 * 60 * 60 * _x_)

#define NUM_SECS_IN_DAY (24 * 3600)
#define NUM_SECS_IN_HOUR (3600)
#define NUM_SECS_IN_MIN (60)



/*RTC Interrupt Control Register Bit Define*/

#define STPW_INT_EN     0x0001
#define ALM_INT_EN      0x0002
#define SEC_INT_EN      0x0004
#define MIN_INT_EN      0x0008
#define H_INT_EN        0x0010
#define H24_INT_EN      0x0020
#define DAY_INT_EN      0x0040
#define WC_INT_EN       0x8000

/*RTC Interrupt Status Register  bit define */
#define STPW_EVT_FG     0x0001
#define ALM_EVT_FG      0x0002
#define SEC_EVT_FG      0x0004
#define MIN_EVT_FG      0x0008
#define H_EVT_FG     	0x0010
#define H24_EVT_FG      0x0020
#define DAY_EVT_FG      0x0040
#define WP_EVT_FG       0x4000
#define WC_EVT_FG       0x8000

/* PreScaler Enable Register bit define */
#define PRESCALE_EN     0x0001

#define RTC_SWCNT_OFF   _IO('p', 0xF0)
#define RTC_SWCNT_ON    _IO('p', 0xF1)
#define RTC_SWCNT_SET   _IOW('p', 0xF2, unsigned long) 
#define RTC_SWCNT_RD    _IOR('p', 0xF3, unsigned long) 



