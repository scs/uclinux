/*
 * libc/sysdeps/linux/bfin/clone.c -- `clone' syscall for linux/blackfin
 *
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License.  See the file COPYING.LIB in the main
 * directory of this archive for more details.
 *
 */

#include <asm/unistd.h>

int
clone (int (*fn)(void *arg), void *child_stack, int flags, void *arg)
{
	long rval = -1, arg0;
	
	if (fn && child_stack) {

	__asm__ __volatile__ ("r1 = %1;"
			"r0 = %2;"
			"P0 = 0x78;"
			"excpt 0;"	 /*Call sys_clone*/
			"%0  = r0;"
			: "=d" (rval)
			: "a" (child_stack), "a" (flags)
			: "CC", "R0", "R1", "P0");
			
		if (rval == 0) {
		/* In child thread, call FN and exit.  */
		arg0 = (*fn) (arg);
		__asm__ __volatile__ (
			"P0 = 0x1;" 	 /* should be need to pass arg0 to exit sys call*/
			"excpt 0;"	 /*Call sys_exit*/
			: : : "P0");
		}
	}
	return rval;
}

