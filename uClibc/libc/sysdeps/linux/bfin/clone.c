/*
 * libc/sysdeps/linux/blackfin/clone.c -- `clone' syscall for linux/blackfin
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
     long rval;
      __asm__ __volatile__ ("r1 = %2;"
		    "r0 = %3;"
		    "r5 = __NR_clone;"
		    "excpt 0;"			/*Call sys_clone*/
		    "%0  = r0;"
		    "r0 = %4;"
		    "sp += -16;"
		    "call (%1);"		/*Execute function fn(arg)*/
		    "sp += 16;"
		    "r5 = __NR_exit;"
		    "excpt 0;"			/*Call sys_exit*/
		    : "=d" (rval)
		    : "a" (fn), "a" (child_stack), "a" (flags), "a" (arg)
		    : "CC", "R0", "R1", "R5");
  return rval;
}
