#include <native/heap.h>

RT_HEAP heap_desc;

void *shared_mem; /* Start address of the shared memory segment */

/* A shared memory segment with Xenomai is implemented as a mappable
   real-time heap object managed as a single memory block. In this
   mode, the allocation routine always returns the start address of
   the heap memory to all callers, and the free routine always leads
   to a no-op. */

int main (int argc, char *argv[])

{
    int err;

    /* Bind to a shared heap which has been created elsewhere, either
       in kernel or user-space. Here we cannot wait and the heap must
       be available at once, since the caller is not a Xenomai-enabled
       thread. The heap should have been created with the H_SHARED
       mode set. */

    err = rt_heap_bind(&heap_desc,"SomeShmName",TM_NONBLOCK);

    if (err)
	fail();

    /* Get the address of the shared memory segment. The "size" and
       "timeout" arguments are unused here. */
    rt_heap_alloc(&heap_desc,0,TM_NONBLOCK,&shared_mem);

    /* ... */
}

void cleanup (void)

{
    /* We need to unbind explicitly from the heap in order to
       properly release the underlying memory mapping. Exiting the
       process unbinds all mappings automatically. */
    rt_heap_unbind(&heap_desc);
}
