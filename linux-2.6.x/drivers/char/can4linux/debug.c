/* Can_debug
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
#include "defs.h"


/* default debugging level */

#if DEBUG
# ifndef DEFAULT_DEBUG
  unsigned int   dbgMask  = \
    (DBG_ENTRY | DBG_EXIT | DBG_BRANCH | DBG_DATA | DBG_INTR | DBG_1PPL)
    & ~DBG_ALL;
# else
unsigned int   dbgMask  = 0;
# endif
#else
unsigned int   dbgMask  = 0;
#endif

/* Print the string to the appropriate tty, the one
 * the current task uses */
#ifdef DEBUG
void print_tty(const char *fmt, ...)
{
#if 0
  /* The tty for the current task */
  struct tty_struct *my_tty = current->tty;
  /* If my_tty is NULL, it means that the current task
   * has no tty you can print to (this is possible, for
   * example, if it's a daemon). In this case, there's
   * nothing we can do. */
  if(my_tty != NULL)
  {
    va_list args;
    static char str[1024];
    int strlength = 0;

    va_start(args, fmt);
    strcpy(str, "can: ");
    strlength = vsprintf(str+6, fmt, args);
    strlength += 6;
    va_end(args);

    /* my_tty->driver is a struct which holds the tty's
     * functions, one of which (write) is used to
     * write strings to the tty. It can be used to take
     * a string either from the user's memory segment
     * or the kernel's memory segment.
     *
     * The function's first parameter is the tty to
     * write to, because the  same function would
     * normally be used for all tty's of a certain type.
     * The second parameter controls whether the
     * function receives a string from kernel memory
     * (false, 0) or from user memory (true, non zero).
     * The third parameter is a pointer to a string,
     * and the fourth parameter is the length of
     * the string.
     */
    (*(my_tty->driver).write)( my_tty, /* The tty itself */
           0, /* We don't take the string from user space */
           str, /* String */
           strlength);  /* Length */

    /* ttys were originally hardware devices, which
     * (usually) adhered strictly to the ASCII standard.
     * According to ASCII, to move to a new line you
     * need two characters, a carriage return and a
     * line feed. In Unix, on the other hand, the
     * ASCII line feed is used for both purposes - so
     * we can't just use \n, because it wouldn't have
     * a carriage return and the next line will
     * start at the column right
     *                          after the line feed.
     *
     * BTW, this is the reason why the text file
     * format is different between Unix and Windows.
     * In CP/M and its derivatives, such as MS-DOS and
     * Windows, the ASCII standard was strictly
     * adhered to, and therefore a new line requires
     * both a line feed and a carriage return.
     */
    (*(my_tty->driver).write)(my_tty,  0, "\015\012", 2);
  }
#endif /* 0 */
}
#else
#endif /* DEBUG */

