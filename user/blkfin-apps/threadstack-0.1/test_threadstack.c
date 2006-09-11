/*
   test_threadstack.c
   David Rowe 
   11/5/06

   Test program for thread stack functions.
*/

#include <stdio.h>
#include <bits/local_lim.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include "threadstack.h"

#define PTHREAD_ATTR_STACKSIZE 100*1024

int finish;
int start;

void *thread_func(void *data) {
  char  x[1000];

  x[999] = 100;

  start = 1;
  while(!finish)
    usleep(1000);

  return NULL;
}

int main() {
  pthread_attr_t attr;
  pthread_t      thread;
  int            errno;
  void          *threadReturn;

  start = 0;
  finish = 0;

  pthread_attr_init(&attr);

  errno = pthread_attr_setstacksize(&attr, PTHREAD_ATTR_STACKSIZE);
  if (errno) {
    printf("pthread_attr_setstacksize returned non-zero: %s\n", 
	   strerror(errno));
  }
  
  errno = pthread_create(&thread, &attr, thread_func, NULL); 
  if (errno) {
    printf("pthread_create returned non-zero: %s\n", 
	   strerror(errno));
  }

  while(!start)
    usleep(1000);

  /* OK lets have a look at stack params from internal thread data */

  printf("stack used: %d\n", threadstack_used(&thread));
  printf("stack free: %d\n", threadstack_free(&thread));

  /* now shut down */

  finish = 1;
  pthread_join(thread, &threadReturn);

  return 0;
}
