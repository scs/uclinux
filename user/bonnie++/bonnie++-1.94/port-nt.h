#ifndef PORT_NT_H
#define PORT_NT_H

#define _LARGEFILE64_SOURCE
#define OFF_T_PRINTF "%lld"

#define NON_UNIX
typedef char Sync;

// WIN32 here
#include <direct.h>
#define file_read _read
#define file_write _write
#define file_unlink _unlink
#define sys_rmdir _rmdir
#define sys_chdir _chdir
#define sys_getpid _getpid
#define file_lseek _lseeki64
#define file_creat _creat
#define file_open _open
#define file_close _close
#define OFF_TYPE __int64

typedef int ssize_t;
typedef struct _timeb TIMEVAL_TYPE;
typedef int FILE_TYPE;
#define S_IRUSR _S_IREAD
#define S_IWUSR _S_IWRITE
#define fsync _commit
#define make_directory _mkdir
#define HDIR long
#define achName name
typedef int pid_t;
#define sleep(XX) { Sleep((XX) * 1000); }

typedef unsigned int UINT;
typedef unsigned long ULONG;
typedef const char * PCCHAR;
typedef PCCHAR const CPCCHAR;
typedef char * PCHAR;
typedef PCHAR const CPCHAR;
typedef void * PVOID;
typedef PVOID const CPVOID;
typedef const CPVOID CPCVOID;
typedef FILE_TYPE *PFILE_TYPE;

#endif
