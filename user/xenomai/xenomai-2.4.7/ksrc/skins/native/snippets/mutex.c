#include <native/mutex.h>

RT_MUTEX mutex_desc;

int main (int argc, char *argv[])

{
    int err;

    /* Create a mutex; we could also have attempted to bind to some
       pre-existing object, using rt_mutex_bind() and rt_mutex_bind()
       instead of creating it. In any case, priority inheritance is
       automatically enforced for mutual exclusion locks. */

    err = rt_mutex_create(&mutex_desc,"MyMutex");

    /* Now, grab the mutex lock, run the critical section, then
       release the lock: */

    rt_mutex_acquire(&mutex_desc,TM_INFINITE);

    /* ... Critical section ... */
    
    rt_mutex_release(&mutex_desc);

    /* ... */
}

void cleanup (void)

{
    rt_mutex_delete(&mutex_desc);
}
