/*
   threadstack.h
   David Rowe 
   8/5/06
*/

#ifndef __THREADSTACK__
#define __THREADSTACK__

unsigned int threadstack_free(pthread_t *thread);
unsigned int threadstack_used(pthread_t *thread);

#endif
