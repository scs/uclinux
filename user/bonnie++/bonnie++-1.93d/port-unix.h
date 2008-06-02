#ifndef PORT_UNIX_H
#define PORT_UNIX_H




#ifndef _LARGEFILE64_SOURCE

#endif
#ifdef _LARGEFILE64_SOURCE
#define OFF_T_PRINTF "%lld"
#else
#define OFF_T_PRINTF "%d"
#endif

#if 0
#define false 0
#define true 1
#endif

// UNIX here
#define file_read read
#define file_write write
#define file_unlink unlink
typedef struct timeval TIMEVAL_TYPE;
#define sys_rmdir rmdir
#define sys_chdir chdir
#define sys_getpid getpid

#ifdef _LARGEFILE64_SOURCE
#define OFF_TYPE off64_t
#define file_lseek lseek64
#define file_creat creat64
#define file_open open64
#else
#define OFF_TYPE off_t
#define file_lseek lseek
#define file_creat creat
#define file_open open
#endif

#define second_sleep sleep
#define file_close close
#define make_directory(XX) mkdir(XX, S_IRWXU)
typedef int FILE_TYPE;
#define __min min
#define __max max
typedef unsigned int UINT;
typedef unsigned long ULONG;
typedef const char * PCCHAR;
typedef char * PCHAR;
typedef PCHAR const CPCHAR;
typedef PCCHAR const CPCCHAR;
typedef void * PVOID;
typedef PVOID const CPVOID;
typedef const CPVOID CPCVOID;

typedef FILE_TYPE *PFILE_TYPE;

#define _strdup strdup

#ifdef NO_SNPRINTF
#define _snprintf sprintf
#else
#define _snprintf snprintf
#endif

#endif
