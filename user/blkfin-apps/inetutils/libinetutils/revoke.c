/* stub revoke */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>

#if !HAVE_DECL_ERRNO
extern int errno;
#endif

int
revoke (char *path)
{
	(void)path;
#ifdef ENOSYS
  errno = ENOSYS;
#else
  errno = EINVAL; /* ? */
#endif
  return -1;
}
