/*
 * can_close - can4linux CAN driver module
 *
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 * 
 * Copyright (c) 2001 port GmbH Halle/Saale
 * (c) 2001 Heinz-Jürgen Oertel (oe@port.de)
 *          Claus Schroeter (clausi@chemie.fu-berlin.de)
 * derived from the the LDDK can4linux version
 *     (c) 1996,1997 Claus Schroeter (clausi@chemie.fu-berlin.de)
 *------------------------------------------------------------------
 * $Header$
 *
 *--------------------------------------------------------------------------
 *
 *
 *
 *--------------------------------------------------------------------------
 */


/**
* \file close.c
* \author Heinz-Jürgen Oertel, port GmbH
* $Revision$
* $Date$
*
*
*/
/*
*
*/
#include <linux/pci.h>
#include "defs.h"

extern int Can_isopen[];   		/* device minor already opened */

#ifndef DOXYGEN_SHOULD_SKIP_THIS
#endif /* DOXYGEN_SHOULD_SKIP_THIS */

/***************************************************************************/
/**
*
* \brief int close(int fd);
* close a file descriptor
* \param fd The descriptor to close.
*
* \b close closes a file descriptor, so that it no longer
*  refers to any device and may be reused.
* \returns
* close returns zero on success, or -1 if an error occurred.
* \par ERRORS
*
* the following errors can occur
*
* \arg \c BADF \b fd isn't a valid open file descriptor 
*

*/
__LDDK_CLOSE_TYPE can_close ( __LDDK_CLOSE_PARAM )
{
unsigned int minor = iminor(inode);

    DBGin("can_close");

    CAN_StopChip(minor);


    /* call this before freeing any memory or io area.
     * this can contain registers needed by Can_FreeIrq()
     */
    Can_FreeIrq(minor, IRQ[minor]);


    /* should the resources be released in a manufacturer specific file?
     * is it always depending on the hardware?
     */

    /* since Vx.y (2.4?) macros defined in ioport.h,
       called is  __release_region()  */
#if defined(CAN_PORT_IO) && !defined(KVASER_PCICAN)
    release_region(Base[minor], can_range[minor] );
#else
# if defined(CAN_INDEXED_PORT_IO)
    release_region(Base[minor],2);
# else
#  ifndef CAN4LINUX_PCI
    /* release I/O memory mapping -> release virtual memory */
    iounmap((void*)Base[minor]);
    /* Release the memory region */
    release_mem_region(Base[minor], can_range[minor]);
#  endif
# endif
#endif

#ifdef CAN_USE_FILTER
    Can_FilterCleanup(minor);
#endif

    /* printk("CAN module %d has been closed\n",minor); */

    if(Can_isopen[minor] > 0) {
	--Can_isopen[minor];		/* flag device as free */
	/* MOD_DEC_USE_COUNT; */
	DBGout();
	return 0;
    }

    DBGout();
    return -EBADF;
}
