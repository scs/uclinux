using namespace std;

#include <stdlib.h>
#ifdef OS2
#define INCL_DOSFILEMGR
#define INCL_BASE
#define INCL_DOSMISC
#endif

#include "duration.h"
#ifdef OS2
#include "os2-perfutil.h"
/*
   Convert 8-byte (low, high) time value to double
*/
#define LL2D(high, low) (4294967296.0*double(high) + double(low))
#else
#ifdef WIN32
#define TIMEVAL_TO_DOUBLE(XX) (double((XX).time) + double((XX).millitm) / 1000.0)
#else
#define TIMEVAL_TO_DOUBLE(XX) (double((XX).tv_sec) + double((XX).tv_usec) / 1000000.0)
#endif

#endif
#ifndef NON_UNIX
#include "conf.h"
#include <unistd.h>
#include <sys/resource.h>
#include <sys/time.h>

#ifdef HAVE_ALGORITHM
#include <algorithm>
#else
#ifdef HAVE_ALGO
#include <algo>
#else
#include <algo.h>
#endif
#endif

#endif

Duration_Base::Duration_Base()
 : m_start(0.0)
 , m_max(0.0)
{
}

double Duration_Base::start()
{
  getTime(&m_start);
  return m_start;
}

double Duration_Base::stop()
{
  double tv;
  getTime(&tv);
  double ret;
  ret = tv - m_start;
  m_max = __max(m_max, ret);
  return ret;
}

bool Duration::getTime(double *tv)
{
#ifdef OS2
  ULONG t = 0;
  ULONG rc = DosQuerySysInfo(QSV_MS_COUNT, QSV_MS_COUNT, PVOID(&t), sizeof(t));
  if(rc)
    return true;
  *tv = double(t) * 1000.0;
#else
  TIMEVAL_TYPE t;
#ifdef WIN32
  _ftime(&t);
#else
  if (gettimeofday(&t, static_cast<struct timezone *>(NULL)) == -1)
    return true;
#endif
  *tv = TIMEVAL_TO_DOUBLE(t);
#endif
  return false;
}

#ifndef WIN32
bool CPU_Duration::getTime(double *tv)
{
#ifdef NON_UNIX
#ifdef OS2
  CPUUTIL     CPUUtil;
 
  ULONG rc = DosPerfSysCall(CMD_KI_RDCNT,(ULONG) &CPUUtil, 0, 0);
  if(rc)
    io_error("times", true);
  *tv = LL2D(CPUUtil.ulBusyHigh, CPUUtil.ulBusyLow)
       + LL2D(CPUUtil.ulIntrHigh, CPUUtil.ulIntrLow);
#else
  return true;
#endif
#else
  struct rusage res_usage;
 
  getrusage(RUSAGE_SELF, &res_usage);
  *tv = TIMEVAL_TO_DOUBLE(res_usage.ru_utime) + TIMEVAL_TO_DOUBLE(res_usage.ru_stime);
#endif
  return false;
}
#endif
