#include "bonnie.h"
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>

#ifdef NON_UNIX
#ifdef OS2
#else
#include <windows.h>
#include <io.h>
#endif

#else

#include <dirent.h>
#include <unistd.h>
#include <sys/wait.h>
#include "sync.h"
#endif

#include <sys/stat.h>
#include <string.h>
#include <limits.h>

#include "bon_io.h"
#include "bon_time.h"


#define END_SEEK_PROCESS INT_MIN

CFileOp::~CFileOp()
{
  Close();
  if(m_name)
  {
    unlink(m_name);
    free(m_name);
  }
  delete m_buf;
}

Thread *CFileOp::newThread(int threadNum)
{
  return new CFileOp(threadNum, this);
}

CFileOp::CFileOp(int threadNum, CFileOp *parent)
 : Thread(threadNum, parent)
 , m_timer(parent->m_timer)
 , m_file_size(parent->m_file_size)
 , m_fd(-1)
 , m_isopen(false)
 , m_name(PCHAR(malloc(strlen(parent->m_name) + 5)))
 , m_sync(parent->m_sync)
 , m_chunk_bits(parent->m_chunk_bits)
 , m_chunk_size(parent->m_chunk_size)
 , m_total_chunks(parent->m_total_chunks)
 , m_buf(new char[m_chunk_size])
{
  strcpy(m_name, parent->m_name);
}

int CFileOp::action(PVOID)
{
  struct report_s seeker_report;
  if(reopen(false))
    return 1;
  int ticket;
  int rc;
  Duration dur, test_time;
  rc = Read(&ticket, sizeof(ticket), 0);
#ifndef WIN32
  CPU_Duration test_cpu;
#endif
  test_time.getTime(&seeker_report.StartTime);
#ifndef WIN32
  test_cpu.start();
#endif
  if(rc == sizeof(ticket) && ticket != END_SEEK_PROCESS) do
  {
    bool update = false;
    if(ticket < 0)
    {
      ticket = abs(ticket);
      update = true;
    }
    dur.start();
    if(doseek(ticket % m_total_chunks, update) )
      return 1;
    dur.stop();
  } while((rc = Read(&ticket, sizeof(ticket), 0)) == sizeof(ticket)
         && ticket != END_SEEK_PROCESS);

  if(rc != sizeof(ticket))
  {
    fprintf(stderr, "Can't read ticket.\n");
    return 1;
  }
  Close();
  // seeker report is start and end times, CPU used, and latency
  test_time.getTime(&seeker_report.EndTime);
#ifndef WIN32
  seeker_report.CPU = test_cpu.stop();
#endif
  seeker_report.Latency = dur.getMax();
  if(Write(&seeker_report, sizeof(seeker_report), 0) != sizeof(seeker_report))
  {
    fprintf(stderr, "Can't write report.\n");
    return 1;
  }
  return 0;
}

int CFileOp::seek_test(Rand &r, bool quiet, Sync &s)
{
  int seek_tickets[SeekProcCount + Seeks];
  int next;
  for(next = 0; next < Seeks; next++)
  {
    seek_tickets[next] = r.getNum();
    if(seek_tickets[next] < 0)
      seek_tickets[next] = abs(seek_tickets[next]);
    if(seek_tickets[next] % UpdateSeek == 0)
      seek_tickets[next] = -seek_tickets[next];
  }
  for( ; next < (Seeks + SeekProcCount); next++)
    seek_tickets[next] = END_SEEK_PROCESS;
  if(reopen(false))
    return 1;
  go(NULL, SeekProcCount);

  sleep(3);
#ifndef NON_UNIX
  if(s.decrement_and_wait(Lseek))
    return 1;
#endif
  if(!quiet) fprintf(stderr, "start 'em...");
  if(Write(seek_tickets, sizeof(seek_tickets), 0) != int(sizeof(seek_tickets)) )
  {
    fprintf(stderr, "Can't write tickets.\n");
    return 1;
  }
  Close();
  for (next = 0; next < SeekProcCount; next++)
  { /* for each child */
    struct report_s seeker_report;

    int rc;
    if((rc = Read(&seeker_report, sizeof(seeker_report), 0))
        != sizeof(seeker_report))
    {
      fprintf(stderr, "Can't read from pipe, expected %d, got %d.\n"
                    , int(sizeof(seeker_report)), rc);
      return 1;
    }

    /*
     * each child writes back its CPU, start & end times.  The elapsed time
     *  to do all the seeks is the time the first child started until the
     *  time the last child stopped
     */
    m_timer.add_delta_report(seeker_report, Lseek);
#ifdef OS2
    TID status = 0;
    if(DosWaitThread(&status, DCWW_WAIT))
//#else
//    int status = 0;
//    if(wait(&status) == -1)
#endif
//      return io_error("wait");
    if(!quiet) fprintf(stderr, "done...");
  } /* for each child */
  if(!quiet) fprintf(stderr, "\n");
  return 0;
}

int CFileOp::seek(int offset, int whence)
{
  OFF_TYPE rc;
  OFF_TYPE real_offset = offset;
  real_offset *= m_chunk_size;
#ifdef OS2
  unsigned long actual;
  rc = DosSetFilePtr(m_fd, real_offset, whence, &actual);
  if(rc != 0) rc = -1;
#else
  rc = file_lseek(m_fd, real_offset, whence);
#endif

  if(rc == OFF_TYPE(-1))
  {
    sprintf(m_buf, "Error in lseek to chunk %d(" OFF_T_PRINTF ")", offset, real_offset);
    perror(m_buf);
    return rc;
  }
  return 0;
}

int CFileOp::read_block(PVOID buf)
{
  int total = 0;
  bool printed_error = false;
  while(total != m_chunk_size)
  {
#ifdef OS2
    unsigned long actual;
    int rc = DosRead(m_fd, buf, m_chunk_size - total, &actual);
    if(rc)
      rc = -1;
    else
      rc = actual;
#else
    int rc = file_read(m_fd, buf, m_chunk_size - total);
#endif
    if(rc == -1)
    {
      io_error("re-write read"); // exits program
    }
    else if(rc != m_chunk_size)
    {
      if(!printed_error)
      {
        fprintf(stderr, "Can't read a full block, only got %d bytes.\n", rc);
        printed_error = true;
        if(rc == 0)
          return -1;
      }
    }
    total += rc;
  }
  return total;
}

int CFileOp::read_block_byte(char *buf)
{
  char next;
  for(int i = 0; i < m_chunk_size; i++)
  {
    if(read(m_fd, &next, 1) != 1)
    {
      fprintf(stderr, "Can't read a byte\n");
      return -1;
    }
    /* just to fool optimizers */
    buf[next]++;
  }

  return 0;
}

int CFileOp::write_block(PVOID buf)
{
#ifdef OS2
  unsigned long actual;
  int rc = DosWrite(m_fd[m_file_ind], buf, m_chunk_size, &actual);
  if(rc)
    rc = -1;
  else
    rc = 0;
  if(actual != m_chunk_size)
    rc = -1;
#else
  int rc = ::write(m_fd, buf, m_chunk_size);
  if(rc != m_chunk_size)
  {
    perror("Can't write block.");
    return -1;
  }
#endif
  return rc;
}

int CFileOp::write_block_byte()
{
  for(int i = 0; i < m_chunk_size; i++)
  {
    char c = i & 0x7f;
    if(write(m_fd, &c, 1) != 1)
    {
      fprintf(stderr, "Can't write() - disk full?\n");
      return -1;
    }
  }
  return 0;
}

int CFileOp::Open(CPCCHAR base_name, bool create)
{
  m_name = PCHAR(malloc(strlen(base_name) + 5));
  strcpy(m_name, base_name);
  return reopen(create);
}

CFileOp::CFileOp(BonTimer &timer, int file_size, int chunk_bits, bool use_sync)
 : m_timer(timer)
 , m_file_size(file_size)
 , m_fd(-1)
 , m_isopen(false)
 , m_name(NULL)
 , m_sync(use_sync)
 , m_chunk_bits(chunk_bits)
 , m_chunk_size(1 << m_chunk_bits)
 , m_total_chunks(Unit / m_chunk_size * file_size)
 , m_buf(new char[m_chunk_size])
{
  if(m_total_chunks / file_size * m_chunk_size != Unit)
  {
    fprintf(stderr, "File size %d too big for chunk size %d\n", file_size, m_chunk_size);
    exit(1);
  }
}

int CFileOp::reopen(bool create)
{
  if(m_isopen) Close();

  m_isopen = true;
  if(m_open(m_name, create))
    return 1;
  return 0;
}

int CFileOp::m_open(CPCCHAR base_name, bool create)
{
#ifdef OS2
  ULONG createFlag;
#else
  int flags;
#endif
  if(create)
  { /* create from scratch */
    file_unlink(base_name);
#ifdef OS2
    createFlag = OPEN_ACTION_CREATE_IF_NEW | OPEN_ACTION_REPLACE_IF_EXISTS;
#else
    flags = O_RDWR | O_CREAT | O_EXCL;
#ifdef WIN32
    flags |= O_BINARY;
#endif

#endif
  }
  else
  {
#ifdef OS2
    createFlag = OPEN_ACTION_OPEN_IF_EXISTS;
#else
    flags = O_RDWR;
#ifdef WIN32
    flags |= O_BINARY;
#else
#ifdef _LARGEFILE64_SOURCE
    flags |= O_LARGEFILE;
#endif
#endif

#endif
  }
#ifdef OS2
  ULONG action = 0;
  ULONG rc = DosOpen(base_name, &m_fd, &action, 0, FILE_NORMAL, createFlag
                   , OPEN_FLAGS_SEQUENTIAL | OPEN_SHARE_DENYNONE | OPEN_ACCESS_READWRITE
                   , NULL);
  if(rc)
    m_fd = -1;
#else
  m_fd = file_open(base_name, flags, S_IRUSR | S_IWUSR);
#endif

  if(m_fd == -1)
  {
    fprintf(stderr, "Can't open file %s\n", base_name);
    return -1;
  }
  return 0;
}

void CFileOp::Close()
{
  if(!m_isopen)
    return;
  if(m_fd != -1)
  {
    if(fsync(m_fd))
      fprintf(stderr, "Can't sync file.\n");
    file_close(m_fd);
  }
  m_isopen = false;
  m_fd = -1;
}


/*
 * Do a typical-of-something random I/O.  Any serious application that
 *  has a random I/O bottleneck is going to be smart enough to operate
 *  in a page mode, and not stupidly pull individual words out at
 *  odd offsets.  To keep the cache from getting too clever, some
 *  pages must be updated.  However an application that updated each of
 *  many random pages that it looked at is hard to imagine.
 * However, it would be wrong to put the update percentage in as a
 *  parameter - the effect is too nonlinear.  Need a profile
 *  of what Oracle or Ingres or some such actually does.
 * Be warned - there is a *sharp* elbow in this curve - on a 1-MiB file,
 *  most substantial unix systems show >2000 random I/Os per second -
 *  obviously they've cached the whole thing and are just doing buffer
 *  copies.
 */
int
CFileOp::doseek(unsigned int where, bool update)
{
  if (seek(where, SEEK_SET) == -1)
    return -1;
  if (read_block(PVOID(m_buf)) == -1)
    return -1;

  /* every so often, update a block */
  if (update)
  { /* update this block */

    /* touch a byte */
    m_buf[where % m_chunk_size]--;
    if(seek(where, SEEK_SET) == -1)
      return io_error("lseek in doseek update");
    if (write_block(PVOID(m_buf)) == -1)
      return -1;
    if(m_sync)
    {
      if(fsync(m_fd))
      {
        fprintf(stderr, "Can't sync file.\n");
        return -1;
      }
    }
  } /* update this block */
  return 0;
}

