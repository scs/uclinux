/* util.h ....... error message utilities.
 *                C. Scott Ananian <cananian@alumni.princeton.edu>
 *
 * $Id$
 */

#ifndef INC_UTIL_H
#define INC_UTIL_H

#include <syslog.h>
#include <stdio.h>

#ifdef LOG_TO_STDERR
	#define	logmsg(a...) ({ fprintf(stderr, a); fputc('\n', stderr); })
#else
	#define logmsg(a...) syslog(LOG_INFO, a)
#endif

#ifdef PPTPDEBUG
	#define pptp_debug(a...) logmsg(a)
#else
	#define pptp_debug(a...)
#endif

#undef assert
#define assert(x) \
	if (!(x)) logmsg("%s,%d ***ASSERT*** - " #x "\n",__FILE__,__LINE__)

#endif /* INC_UTIL_H */
