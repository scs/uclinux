/* Changes made by Tony Kou    Lineo, Inc    May 2001	*/

#include <linux/types.h>
#include <linux/autoconf.h>

void * memcpy(void * to, const void * from, size_t n)
{
  const char *c_from = from;
  char *c_to = to;
  while (n-- > 0)
    *c_to++ = *c_from++;
  return((void *) to);
}
