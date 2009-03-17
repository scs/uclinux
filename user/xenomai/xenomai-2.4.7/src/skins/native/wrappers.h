#ifndef _XENO_WRAPPERS_H
#define _XENO_WRAPPERS_H

#include <sys/types.h>
#include <pthread.h>

int __real_pthread_create(pthread_t *tid,
			  const pthread_attr_t * attr,
			  void *(*start) (void *), void *arg);

int __real_pthread_setschedparam(pthread_t thread,
				 int policy, const struct sched_param *param);

int __real_pthread_kill(pthread_t tid, int sig);

int __real_open(const char *path, int oflag, ...);

int __real_close(int fd);

int __real_ioctl(int fd, int request, ...);

void *__real_mmap(void *addr,
		  size_t len, int prot, int flags, int fd, off_t off);

int __real_munmap(void *addr, size_t len);

#endif /* !_XENO_WRAPPERS_H */
