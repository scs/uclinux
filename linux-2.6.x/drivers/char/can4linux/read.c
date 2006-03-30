/*
 * can_read - can4linux CAN driver module
 *
 * can4linux -- LINUX CAN device driver source
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
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
 *
 *--------------------------------------------------------------------------
 */


/**
* \file read.c
* \author Heinz-Jürgen Oertel, port GmbH
* $Revision$
* $Date$
*
* Module Description 
* see Doxygen Doc for all possibilities
*
*
*
*/


/* header of standard C - libraries */

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
* \brief ssize_t read(int fd, void *buf, size_t count);
* the read system call
* \param fd The descriptor to read from.
* \param buf The destination data buffer (array of CAN canmsg_t).
* \param count The number of bytes to read.
*
* read() attempts to read up to \a count CAN messages 
* (\b not \b bytes! ) from file descriptor fd
* into the buffer starting at buf.
* buf must be large enough to hold count times the size of 
* one CAN message structure \b canmsg_t.
* 
* \code
int got;
canmsg_t rx[80];			// receive buffer for read()

    got = read(can_fd, rx , 80 );
    if( got > 0) {
      ...
    } else {
	// read returned with error
	fprintf(stderr, "- Received got = %d\n", got);
	fflush(stderr);
    }


* \endcode
*
* \par ERRORS
*
* the following errors can occur
*
* \arg \c EINVAL \b buf points not to an large enough area,
*
* \returns
* On success, the number of CAN messages read is returned
* (zero indicates end of file).
* It is not an  error if this number is
* smaller than the number of messages requested;
* this may happen for example
* because fewer messages are actually available right now,
* or because read() was interrupted by a signal.
* On error, -1 is returned, and errno is set  appropriately.
*
* \internal
*/

__LDDK_READ_TYPE can_read( __LDDK_READ_PARAM )
{
size_t written = 0;
  DBGin("can_read");
  {
	unsigned int minor = __LDDK_MINOR;
	msg_fifo_t *RxFifo = &Rx_Buf[minor];
	canmsg_t *addr; 
	int blocking;

	addr = (canmsg_t *)buffer;
	blocking = !(file->f_flags & O_NONBLOCK);
	
	if( !access_ok( VERIFY_WRITE, buffer, count * sizeof(canmsg_t) )) {
	   DBGout();
	   return -EINVAL;
	}
	/* while( written < count && RxFifo->status == BUF_OK )  */
	while( written < count ) {

	    /* Look if there are currently messages in the rx queue */
	    if( RxFifo->tail == RxFifo->head ) {
		RxFifo->status = BUF_EMPTY;

		if(blocking) {
		    /* printk("empty and blocking, %d = %d\n", */
			/* RxFifo->tail , RxFifo->head ); */
		    if(wait_event_interruptible(CanWait[minor], \
			RxFifo->tail != RxFifo->head ))
			return -ERESTARTSYS;
		} else 
		    break;
	    }	

	    /* copy one message to the user process */
	    __lddk_copy_to_user( (canmsg_t *) &(addr[written]), 
			(canmsg_t *) &(RxFifo->data[RxFifo->tail]),
			sizeof(canmsg_t) );
	    written++;
	    RxFifo->tail = ++(RxFifo->tail) % MAX_BUFSIZE;
	}
    } 
    DBGout();
    return(written);
}
