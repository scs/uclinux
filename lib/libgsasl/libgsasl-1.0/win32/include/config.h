#ifndef _CONFIG_H
#define _CONFIG_H

#define strcasecmp stricmp
#define strncasecmp strnicmp

#define PACKAGE "libgsasl"
#define LOCALEDIR "."

#if _MSC_VER && !__cplusplus
# define inline __inline
#endif

#define EOVERFLOW E2BIG
#define GNULIB_GC_HMAC_MD5 1
#define GNULIB_GC_MD5 1
#define GNULIB_GC_RANDOM 1
#define HAVE_ALLOCA 1
#define HAVE_DECL_GETDELIM 0
#define HAVE_DECL_GETLINE 0
#define HAVE_DECL_STRDUP 1
#define HAVE_DECL__SNPRINTF 1
#define HAVE_FLOAT_H 1
#define HAVE_INCLUDE_NEXT 1
#define HAVE_INTMAX_T 1
#define HAVE_INTTYPES_H 1
#define HAVE_INTTYPES_H_WITH_UINTMAX 1
#define HAVE_LONG_LONG_INT 1
#define HAVE_MEMORY_H 1
#define HAVE_SNPRINTF 1
#define HAVE_STDBOOL_H 1
// #define HAVE_STDINT_H 1
#define HAVE_STDINT_H_WITH_UINTMAX 1
#define HAVE_STDIO_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRDUP 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_UNISTD_H 1
#define HAVE_UNSIGNED_LONG_LONG_INT 1
#define HAVE_WCHAR_H 1
#define HAVE_WCHAR_T 1
#define HAVE_WCSLEN 1
#define HAVE_WINT_T 1
#define HAVE__BOOL 1
#define NAME_OF_NONCE_DEVICE "/dev/urandom"
#define NAME_OF_PSEUDO_RANDOM_DEVICE "/dev/urandom"
#define NAME_OF_RANDOM_DEVICE "/dev/random"

#define STDC_HEADERS 1
#define USE_ANONYMOUS 1
#define USE_CLIENT 1
#define USE_CRAM_MD5 1
#define USE_DIGEST_MD5 1
#define USE_EXTERNAL 1
#define USE_LOGIN 1
#define USE_PLAIN 1
#define USE_SECURID 1
#define USE_SERVER 1

#define restrict
#define __attribute__(x)

#ifndef _AC_STDINT_H
#include <sys/types.h>
#include "ac-stdint.h"
#endif

#endif /* _CONFIG_H */
