#include <unistd.h>
#include <sys/wait.h>

pid_t
waitpid (pid_t pid, int *status, int options)
{
#if defined(HAVE_WAIT4)

  return wait4 (pid, status, options, (struct rusage *)0);

#elif defined(HAVE_WAIT3)

  return wait3 (status, options, (struct rusage *)0);

#else
  errno = ENOSYS;
  return -1;
}
