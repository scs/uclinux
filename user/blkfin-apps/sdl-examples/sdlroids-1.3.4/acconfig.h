#ifndef CONFIG_H
#define CONFIG_H
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
#define RCSID(X) \
 static char *rcsid __attribute__ ((unused)) =X
#elif __GNUC__ == 2
#define RCSID(X) \
 static char *rcsid = X; \
 static void *use_rcsid=(&use_rcsid, (void *)&rcsid)
#else
#define RCSID(X) \
 static char *rcsid = X
#endif

@TOP@

@BOTTOM@
#endif
