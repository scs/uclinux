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

	__asm__ __volatile__ ("r1 = %2;"
			"r0 = %3;"
			"P0 = %1;"
			"excpt 0;"	 /*Call sys_clone*/
			"%0  = r0;"
			: "=d" (rval)
			: "i" (__NR_clone), "a" (child_stack), "a" (flags)
			: "CC", "R0", "R1", "P0");
			
		if (rval == 0) {
		/* In child thread, call FN and exit.  */
		arg0 = (*fn) (arg);
		__asm__ __volatile__ (
			"P0 = %0;" 	 /* should be need to pass arg0 to exit sys call*/
			"excpt 0;"	 /*Call sys_exit*/
			: : "i" (__NR_exit) : "P0");
		}
	}
	return rval;
}

