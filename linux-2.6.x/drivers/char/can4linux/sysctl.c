/* can_sysctl
*
* can4linux -- LINUX CAN device driver source
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * 
 * Copyright (c) 2001 port GmbH Halle/Saale
 * (c) 2001 Heinz-Jürgen Oertel (oe@port.de)
 *          Claus Schroeter (clausi@chemie.fu-berlin.de)
 *------------------------------------------------------------------
 * $Header$
 *
 *--------------------------------------------------------------------------
 *
 *
 * modification history
 * --------------------
 * $Log$
 * Revision 1.1  2006/01/31 09:11:45  hennerich
 * Initial checkin can4linux driver Blackfin BF537/6/4 Task[T128]
 *
 * Revision 1.1  2003/07/18 00:11:46  gerg
 * I followed as much rules as possible (I hope) and generated a patch for the
 * uClinux distribution. It contains an additional driver, the CAN driver, first
 * for an SJA1000 CAN controller:
 *   uClinux-dist/linux-2.4.x/drivers/char/can4linux
 * In the "user" section two entries
 *   uClinux-dist/user/can4linux     some very simple test examples
 *   uClinux-dist/user/horch         more sophisticated CAN analyzer example
 *
 * Patch submitted by Heinz-Juergen Oertel <oe@port.de>.
 *
 *
 *
 */
/*
 * This Template implements the SYSCTL basics, and handler/strategy routines
 * Users may implement own routines and hook them up with the 'handler'		
 * and 'strategy' methods of sysctl.
 * 
 *
 */
#include "defs.h"
#include <linux/mm.h>
#include <linux/sysctl.h>
#include <linux/ctype.h>
/* #include <can_sysctl.h> */



/* #if LINUX_VERSION_CODE >= 131587 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 2, 3)
/* on 2.2 kernels replace default functions with the generic ones */

#define Can_dointvec proc_dointvec
#define Can_dostring proc_dostring
#define Can_sysctl_string sysctl_string

#endif





#define SYSCTL_Can 1

/* ----- Prototypes */
#if LINUX_VERSION_CODE < 131587

extern int Can_dointvec(ctl_table *table, int write, struct file *filp,
		  void *buffer, size_t *lenp);

extern int Can_dostring(ctl_table *table, int write, struct file *filp,
		  void *buffer, size_t *lenp);


extern int Can_sysctl_string(ctl_table *table, int *name, int nlen,
		  void *oldval, size_t *oldlenp,
		  void *newval, size_t newlen, void **context);

#endif

/* ----- global variables accessible through /proc/sys/Can */

char version[] = VERSION;
char IOModel[MAX_CHANNELS];
char Chipset[] =
#if defined(ATCANMINI_PELICAN)
	"SJA1000"
#elif defined(CPC_PCI)
	"SJA1000"
#elif defined(IME_SLIMLINE)
	"SJA1000"
#elif defined(PCM3680)
	"SJA1000"
#elif defined(IXXAT_PCI03)
	"SJA1000"
#elif defined(CCPC104)
	"SJA1000"
#elif defined(MCF5282)
	"FlexCAN"
#else
	""
#endif
;

int IRQ[MAX_CHANNELS] = { 0x0 };
/* dont assume a standard address, always configure,
 * address == 0 means no board available */
unsigned int Base[MAX_CHANNELS] = { 0x0 };
unsigned int AccCode[MAX_CHANNELS];
unsigned int AccMask[MAX_CHANNELS];
int Baud[MAX_CHANNELS];
int Timeout[MAX_CHANNELS];
/* predefined value of the output control register,
* depends of TARGET set by Makefile */
int Outc[MAX_CHANNELS]	  = { 0x0 };
int TxErr[MAX_CHANNELS]   = { 0x0 };
int RxErr[MAX_CHANNELS]   = { 0x0 };
int Overrun[MAX_CHANNELS] = { 0x0 };

#ifdef DEBUG_COUNTER
int Cnt1[MAX_CHANNELS]    = { 0x0 };
int Cnt2[MAX_CHANNELS]    = { 0x0 };
#endif /* DEBUG_COUNTER */

/* ----- the sysctl table */

ctl_table Can_sysctl_table[] = {
 { SYSCTL_VERSION, "version", &version, PROC_VER_LENGTH, 
		 0444, NULL, &Can_dostring , &Can_sysctl_string },
 { SYSCTL_CHIPSET, "Chipset", &Chipset, PROC_CHIPSET_LENGTH, 
		 0444, NULL, &Can_dostring , &Can_sysctl_string },
 { SYSCTL_IOMODEL, "IOModel", &IOModel, MAX_CHANNELS + 1, 
		 0444, NULL, &Can_dostring , &Can_sysctl_string },
 { SYSCTL_IRQ, "IRQ",(void *) IRQ, MAX_CHANNELS*sizeof(int), 
		 0644, NULL, &Can_dointvec , NULL  },
 { SYSCTL_BASE, "Base",(void *) Base, MAX_CHANNELS*sizeof(int), 
		 0644, NULL, &Can_dointvec , NULL  },
 { SYSCTL_BAUD, "Baud",(void *) Baud, MAX_CHANNELS*sizeof(int), 
		 0666, NULL, &Can_dointvec , NULL  },
 { SYSCTL_ACCCODE, "AccCode",(void *) AccCode, MAX_CHANNELS*sizeof(unsigned int), 
		 0644, NULL, &Can_dointvec , NULL  },
 { SYSCTL_ACCMASK, "AccMask",(void *) AccMask, MAX_CHANNELS*sizeof(unsigned int), 
		 0644, NULL, &Can_dointvec , NULL  },
 { SYSCTL_TIMEOUT, "Timeout",(void *) Timeout, MAX_CHANNELS*sizeof(int), 
		 0644, NULL, &Can_dointvec , NULL  },
 { SYSCTL_OUTC, "Outc",(void *) Outc, MAX_CHANNELS*sizeof(int), 
		 0644, NULL, &Can_dointvec , NULL  },
 { SYSCTL_TXERR, "TxErr",(void *) TxErr, MAX_CHANNELS*sizeof(int), 
		 0444, NULL, &Can_dointvec , NULL  },
 { SYSCTL_RXERR, "RxErr",(void *) RxErr, MAX_CHANNELS*sizeof(int), 
		 0444, NULL, &Can_dointvec , NULL  },
 { SYSCTL_OVERRUN, "Overrun",(void *) Overrun, MAX_CHANNELS*sizeof(int), 
		 0444, NULL, &Can_dointvec , NULL  },
 { SYSCTL_DBGMASK, "dbgMask",(void *) &dbgMask, 1*sizeof(int), 
		 0644, NULL, &Can_dointvec , NULL  },
#ifdef DEBUG_COUNTER
/* ---------------------------------------------------------------------- */
 { SYSCTL_CNT1, "cnt1",(void *) Cnt1, MAX_CHANNELS*sizeof(int), 
		 0444, NULL, &Can_dointvec , NULL  },
 { SYSCTL_CNT2, "cnt2",(void *) Cnt2, MAX_CHANNELS*sizeof(int), 
		 0444, NULL, &Can_dointvec , NULL  },
/* ---------------------------------------------------------------------- */
#endif /* DEBUG_COUNTER */
   {0}
};

/* ----- the main directory entry in /proc/sys */

ctl_table Can_sys_table[] = {
	    {SYSCTL_Can, "Can", NULL, 0, 0555, 
                 Can_sysctl_table},	
	    {0}	
};

/* ----- register and unregister entrys */

struct ctl_table_header *Can_systable;

void register_systables(void)
{
    Can_systable = register_sysctl_table( Can_sys_table, 0 );
}

void unregister_systables(void)
{
    unregister_sysctl_table(Can_systable);
}






#if LINUX_VERSION_CODE < 131587


/* ----- default proc handlers */


int Can_dointvec(ctl_table *table, int write, struct file *filp,
		  void *buffer, size_t *lenp)
 {
int *i, vleft, first=1, len, left, neg, val;
#define TMPBUFLEN 20
char buf[TMPBUFLEN], *p;
	
    if (!table->data || !table->maxlen || !*lenp ||
	(filp->f_pos && !write)) {
	    *lenp = 0;
	    return 0;
    }
    
    i = (int *) table->data;
    vleft = table->maxlen / sizeof(int);
    left = *lenp;
    
    for (; left && vleft--; i++, first=0) {
	if (write) {
	    while (left && isspace( get_user((char *) buffer))) {
		left--, ((char *) buffer)++;
	    }
	    if (!left) {
		break;
	    }
	    neg = 0;
	    len = left;
	    if (len > TMPBUFLEN-1) {
		len = TMPBUFLEN-1;
	    }

#if LINUX_VERSION_CODE > 0x20100
	    memcpy_fromio(buf, buffer, len);
#else
	    memcpy_fromfs(buf, buffer, len);
#endif

	    buf[len] = 0;
	    p = buf;
	    if (*p == '-' && left > 1) {
		neg = 1;
		left--, p++;
	    }
	    if (*p < '0' || *p > '9') {
		break;
	    }
	    val = simple_strtoul(p, &p, 0);
	    len = p-buf;
	    if ((len < left) && *p && !isspace(*p)) {
		break;
	    }
	    if (neg) {
		val = -val;
	    }
	    buffer += len;
	    left -= len;
	    *i = val;
	} else {
	    p = buf;
	    if (!first) {
		*p++ = '\t';
	    }
	    sprintf(p, "%d", *i);
	    len = strlen(buf);
	    if (len > left)
		    len = left;
#if LINUX_VERSION_CODE > 0x20100
	    memcpy_toio(buffer, buf, len);
#else
	    memcpy_tofs(buffer, buf, len);
#endif
	    left -= len;
	    buffer += len;
	}
    }

    if (!write && !first && left) {
	put_user('\n', (char *) buffer);
	left--, buffer++;
    }
    if (write) {
	p = (char *) buffer;
	while (left && isspace(get_user(p++))) {
	    left--;
	}
    }
    if (write && first) {
	return -EINVAL;
    }
    *lenp -= left;
    filp->f_pos += *lenp;
    return 0;
}


int Can_dostring(ctl_table *table, int write, struct file *filp,
		  void *buffer, size_t *lenp)
{
int len;
char *p, c;
    
    if (!table->data || !table->maxlen || !*lenp ||
	(filp->f_pos && !write)) {
	    *lenp = 0;
	    return 0;
    }
    
    if (write) {
	    len = 0;
	    p = buffer;
	    while (len < *lenp && (c = get_user(p++)) != 0 && c != '\n') {
		len++;
	    }
	    if (len >= table->maxlen) {
		len = table->maxlen-1;
	    }

#if LINUX_VERSION_CODE > 0x20100
	    memcpy_fromio(table->data, buffer, len);
#else
	    memcpy_fromfs(table->data, buffer, len);
#endif

	    ((char *) table->data)[len] = 0;
	    filp->f_pos += *lenp;
    } else {
	    len = strlen(table->data);
	    if (len > table->maxlen) {
		len = table->maxlen;
	    }
	    if (len > *lenp) {
		len = *lenp;
	    }
	    if (len) {
#if LINUX_VERSION_CODE > 0x20100
		memcpy_toio(buffer, table->data, len);
#else
		memcpy_tofs(buffer, table->data, len);
#endif
	    }
	    if (len < *lenp) {
		    put_user('\n', ((char *) buffer) + len);
		    len++;
	    }
	    *lenp = len;
	    filp->f_pos += len;
    }
    return 0;
}


/* ----- strategy handlers */

int Can_sysctl_string(ctl_table *table, int *name, int nlen,
		  void *oldval, size_t *oldlenp,
		  void *newval, size_t newlen, void **context)
{
int l, len;
    
    if (!table->data || !table->maxlen) 
	    return -ENOTDIR;
    
    if (oldval && oldlenp && get_user(oldlenp)) {
	    len = get_user(oldlenp);
	    l = strlen(table->data);
	    if (len > l) len = l;
	    if (len >= table->maxlen)
		    len = table->maxlen;
#if LINUX_VERSION_CODE > 0x20100
	    memcpy_toio(oldval, table->data, len);
#else
	    memcpy_tofs(oldval, table->data, len);
#endif


	    put_user(0, ((char *) oldval) + len);
	    put_user(len, oldlenp);
    }
    if (newval && newlen) {
	    len = newlen;
	    if (len > table->maxlen)
		    len = table->maxlen;

#if LINUX_VERSION_CODE > 0x20100
	    memcpy_fromio(table->data, newval, len);
#else
	    memcpy_fromfs(table->data, newval, len);
#endif

	    if (len == table->maxlen)
		    len--;
	    ((char *) table->data)[len] = 0;
    }
    return 0;
}

#endif /*version*/











