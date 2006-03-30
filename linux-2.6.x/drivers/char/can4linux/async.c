/*
 * can_async - can4linux CAN driver module
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
 * Copyright (c) 2003  Phil Wilshire ( philwil@sysdcs.com)

 *------------------------------------------------------------------
 * $Header$
 *
 *--------------------------------------------------------------------------
 *
 *
 * modification history
 * --------------------
 * $Log$
 * Revision 1.2  2006/03/30 15:21:45  hennerich
 * Apply Blackfin can4linux patch form port GmbH
 *
 * Revision 1.1  2004/05/14 10:06:53  oe
 * - started supporting async notification
 *
 *
 *
 *--------------------------------------------------------------------------
 */


/**
* \file can_async.c
* \author Phil Wilshire SDCS (philwil@sysdcs.com)
* $Revision$
* $Date$
*
*
*/


/* header of standard C - libraries */
/* #include <linux/module.h>			 */

/* header of common types */

/* shared common header */

/* header of project specific types */

/* project headers */
#include "defs.h"

/* local header */

/* constant definitions
---------------------------------------------------------------------------*/

/* local defined data types
---------------------------------------------------------------------------*/

/* list of external used functions, if not in headers
---------------------------------------------------------------------------*/

/* list of global defined functions
---------------------------------------------------------------------------*/

/* list of local defined functions
---------------------------------------------------------------------------*/

/* external variables
---------------------------------------------------------------------------*/

/* global variables
---------------------------------------------------------------------------*/

/* local defined variables
---------------------------------------------------------------------------*/
/* static char _rcsid[] = "$Id$"; */


/***************************************************************************/
/**
*
* \brief int fasync(int fd, struct file *file, int count);
*
* causes the async handler to be called
* \param fd result of the open call

*
*
* \returns
* return 0 
* or -1 if an error occurred (in which case, errno is set appropriately).
*
* \par ERRORS
* the following errors can occur
* \arg \c ENXIO  the file is a device special file
* and no corresponding device exists.
* \arg \c EINVAL illegal \b minor device number
* \arg \c EINVAL wrong IO-model format in /proc/sys/Can/IOmodel
* \arg \c EBUSY  IRQ for hardware is not available
* \arg \c EBUSY  I/O region for hardware is not available

*/

/*
* a call in the user application of fcntl(fd, F_SETOWN, getpid())
  fills in the structure file->f_owner
  the process id of the calling proces

*/

int can_fasync( __LDDK_FASYNC_PARAM ) /* inode, file, count */
{
int retval = 0;
#if 0
can_data_t *dev = (can_data_t *)file->private_data;

    DBGin("can_fasync");
    {
      retval = fasync_helper(fd, file, count, &dev->fasyncptr);
      DBGprint(DBG_DATA,(" -- async  count %d  retval %d\n", 
			 count, retval));
      if ( retval > 0 )
	retval = 0;
    }
    DBGout();
#endif
    return retval;
}

