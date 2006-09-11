/*
 * Zaptel configuration options 
 *
 */
#ifndef _ZCONFIG_H
#define _ZCONFIG_H

#ifdef __KERNEL__
#include <linux/config.h>
#include <linux/version.h>
#endif

/* Zaptel compile time options */

/*
 * Uncomment to disable calibration and/or DC/DC converter tests
 * (not generally recommended)
 */
/* #define NO_CALIBRATION */
/* #define NO_DCDC */

/*
 * Boost ring voltage (Higher ring voltage, takes more power)
 */
/* #define BOOST_RINGER */

/*
 * Define CONFIG_CALC_XLAW if you have a small number of channels and/or
 * a small level 2 cache, to optimize for few channels
 *
 */
/* #define CONFIG_CALC_XLAW */

/*
 * Define if you want MMX optimizations in zaptel
 *
 * Note: CONFIG_ZAPTEL_MMX is generally incompatible with AMD 
 * processors and can cause system instability!
 * 
 */
/* #define CONFIG_ZAPTEL_MMX */

/*
 * Pick your echo canceller: MARK2, MARK3, STEVE, or STEVE2 :)
 */ 
/* #define ECHO_CAN_STEVE */
/* #define ECHO_CAN_STEVE2 */
/* #define ECHO_CAN_MARK */
#define ECHO_CAN_MARK2
/* #define ECHO_CAN_MARK3 */

/*
 * Uncomment for aggressive residual echo supression under 
 * MARK2 echo canceller
 */
/* #define AGGRESSIVE_SUPPRESSOR */

/*
 * Define to turn off the echo canceler disable tone detector,
 * which will cause zaptel to ignore the 2100 Hz echo cancel disable
 * tone.
 */
/* #define NO_ECHOCAN_DISABLE */

/* udev support */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#define CONFIG_ZAP_UDEV
#endif

/* We now use the linux kernel config to detect which options to use */
/* You can still override them below */
#if defined(CONFIG_HDLC) || defined(CONFIG_HDLC_MODULE)
/* #define CONFIG_ZAPATA_NET */ /* NEVER implicitly turn on ZAPATA_NET */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,4,19)
#define CONFIG_OLD_HDLC_API
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,23)
/* Starting with 2.4.23 the kernel hdlc api changed again */
/* Now we have to use hdlc_type_trans(skb, dev) instead of htons(ETH_P_HDLC) */
#define ZAP_HDLC_TYPE_TRANS
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,3)
#define HDLC_MAINTAINERS_ARE_MORE_STUPID_THAN_I_THOUGHT
#endif
#endif
#endif
#ifdef CONFIG_PPP
#define CONFIG_ZAPATA_PPP
#endif

/*
 * Uncomment CONFIG_ZAPATA_NET to enable SyncPPP, CiscoHDLC, and Frame Relay
 * support.
 */
/* #define CONFIG_ZAPATA_NET */

/*
 * Uncomment CONFIG_OLD_HDLC_API if your are compiling with ZAPATA_NET
 * defined and you are using the old kernel HDLC interface (or if you get
 * an error about ETH_P_HDLC while compiling).
 */
/* #define CONFIG_OLD_HDLC_API */

/*
 * Uncomment for Generic PPP support (i.e. ZapRAS)
 */
/* #define CONFIG_ZAPATA_PPP */
/*
 * Uncomment to enable "watchdog" to monitor if interfaces
 * stop taking interrupts or otherwise misbehave
 */
/* #define CONFIG_ZAPTEL_WATCHDOG */

/* Tone zone info */
#define DEFAULT_TONE_ZONE 0

/*
 * Uncomment for Non-standard FXS groundstart start state (A=Low, B=Low)
 * particularly for CAC channel bank groundstart FXO ports.
 */
/* #define CONFIG_CAC_GROUNDSTART */

/*
 * Uncomment if you happen have an early TDM400P Rev H which
 * sometimes forgets its PCI ID to have wcfxs match essentially all
 * subvendor ID's
 */
/* #define TDM_REVH_MATCHALL */

#endif
