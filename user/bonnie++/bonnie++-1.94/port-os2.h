#ifndef PORT_H
#define PORT_H

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#ifdef _LARGEFILE64_SOURCE
#define OFF_T_PRINTF "%lld"
#else
#define OFF_T_PRINTF "%d"
#endif


#define NON_UNIX
typedef char Sync;
typedef enum
{
  false = 0,
  true = 1
} bool;

#define INCL_DOSQUEUES
#define INCL_DOSPROCESS
#include <os2.h>

#define file_read DosRead
#define file_write DosWrite
#define NO_SNPRINTF
#define HAVE_MIN_MAX
typedef ULONG TIMEVAL_TYPE;
#define chdir(XX) DosSetCurrentDir(XX)
#define fsync(XX) DosResetBuffer(XX)
#define sys_rmdir(XX) DosDeleteDir(XX)
#define sys_chdir(XX) DosSetCurrentDir(XX)
#define file_findclose DosFindClose
#define file_close DosClose
#define make_directory(XX) DosCreateDir(XX, NULL)
typedef HFILE FILE_TYPE;
#define pipe(XX) DosCreatePipe(&XX[0], &XX[1], 8 * 1024)
#define sleep(XX) DosSleep((XX) * 1000)
#define exit(XX) DosExit(EXIT_THREAD, XX)
typedef ULONG pid_t;

typedef FILE_TYPE *PFILE_TYPE;

#ifdef NO_SNPRINTF
#define _snprintf sprintf
#else
#define _snprintf snprintf
#endif

#endif
