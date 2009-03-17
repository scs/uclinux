#include <native/sem.h>

#define SEM_INIT 1	 /* Initial semaphore count */
#define SEM_MODE S_FIFO	 /* Wait by FIFO order */

RT_SEM sem_desc;

void foo (void)

{
    int err;

    /* Create a semaphore; we could also have attempted to bind to
       some pre-existing object, using rt_sem_bind() instead of
       creating it. */

    err = rt_sem_create(&sem_desc,"MySemaphore",SEM_INIT,SEM_MODE);

    for (;;) {

    	/* Now, wait for a semaphore unit... */
    	rt_sem_p(&sem_desc,TM_INFINITE);

	/* ... */

	/* then release it. */
	rt_sem_v(&sem_desc);

	/* ... */
    }
}

void cleanup (void)

{
    rt_sem_delete(&sem_desc);
}
