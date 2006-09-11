/*
   threadstack.c
   David Rowe 
   8/5/06

   Functions to return information about the state of a thread's stack.

   Assumes that the memory used for the stack is initially set to all
   0's and that when we find a non-zero value that represents the
   current "high water mark" of stack useage.
*/

#include <bits/local_lim.h>
#include <pthread.h>
#include <internals.h> /* from uClibc libpthread */
#include "threadstack.h"

uint32_t threadstack_free(pthread_t *thread)
{
  pthread_handle handle = thread_handle(*thread);
  pthread_descr  th = handle->h_descr;
  uint32_t      *p;

  for(p=(uint32_t*)handle->h_bottom; 
      ((p<(uint32_t*)th) && (*p==0)); 
      p++);
  
  return (uint32_t)p - (uint32_t)handle->h_bottom;
}
  
uint32_t threadstack_used(pthread_t *thread)
{
  pthread_handle handle = thread_handle(*thread);
  pthread_descr  th = handle->h_descr;
  uint32_t      *p;

  for(p=(uint32_t*)handle->h_bottom; 
      ((p<(uint32_t*)th) && (*p==0)); 
      p++);
  
  return (uint32_t)th - (uint32_t)p;
}

