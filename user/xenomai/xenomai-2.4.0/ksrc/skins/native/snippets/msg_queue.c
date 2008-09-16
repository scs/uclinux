#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <native/task.h>
#include <native/queue.h>

#define TASK_PRIO  99 /* Highest RT priority */
#define TASK_MODE  0  /* No flags */
#define TASK_STKSZ 0  /* Stack size (use default one) */

RT_QUEUE q_desc;

RT_TASK task_desc;

void consumer (void *cookie)

{
    ssize_t len;
    void *msg;
    int err;

    /* Bind to a queue which has been created elsewhere, either in
       kernel or user-space. The call will block us until such queue
       is created with the expected name. The queue should have been
       created with the Q_SHARED mode set, which is implicit when
       creation takes place in user-space. */

    err = rt_queue_bind(&q_desc,"SomeQueueName",TM_INFINITE);

    if (err)
	fail();

    /* Collect each message sent to the queue by the queuer() routine,
       until the queue is eventually removed from the system by a call
       to rt_queue_delete(). */

    while ((len = rt_queue_receive(&q_desc,&msg,TM_INFINITE)) > 0)
	{
	printf("received message> len=%d bytes, ptr=%p, s=%s\n",
	       len,msg,(const char *)msg);
	rt_queue_free(&q_desc,msg);
	}

    /* We need to unbind explicitly from the queue in order to
       properly release the underlying memory mapping. Exiting the
       process unbinds all mappings automatically. */

    rt_queue_unbind(&q_desc);

    if (len != -EIDRM)
	/* We received some unexpected error notification. */
	fail();

    /* ... */
}

int main (int argc, char *argv[])

{
    static char *messages[] = { "hello", "world", NULL };
    int n, len;
    void *msg;

    mlockall(MCL_CURRENT|MCL_FUTURE);

    err = rt_task_create(&task_desc,
			 "MyTaskName",
			 TASK_STKSZ,
			 TASK_PRIO,
			 TASK_MODE);
    if (!err)
	rt_task_start(&task_desc,&task_body,NULL);

    /* ... */

    for (n = 0; messages[n] != NULL; n++)
	{
	len = strlen(messages[n]) + 1;
	/* Get a message block of the right size. */
	msg = rt_queue_alloc(&q_desc,len);

	if (!msg)
	    /* No memory available. */
	    fail();

	strcpy(msg,messages[n]);
	rt_queue_send(&q_desc,msg,len,Q_NORMAL);
	}

    rt_task_delete(&task_desc);
}
