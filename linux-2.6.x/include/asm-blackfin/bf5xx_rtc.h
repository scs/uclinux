/*
 * BF533 RTC support functions.
 */

#ifndef _BF533_RTC_H_
#define _BF533_RTC_H_

#include <linux/time.h>

/* Intialize the BF533 RTC */
int rtc_init(void);

/* Get the time stored in RTC. time_in_seconds is no. of seconds from Jan 1970 */
int rtc_get(time_t * time_in_seconds);

/* Set a new time in the RTC. time_in_seconds is no. of seconds from Jan 1970  */
int rtc_set(time_t time_in_seconds);

#endif
