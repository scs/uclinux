#include <sys/mman.h>
#include <native/task.h>
#include <native/intr.h>

#define IRQ_NUMBER 7  /* Intercept interrupt #7 */
#define TASK_PRIO  99 /* Highest RT priority */
#define TASK_MODE  0  /* No flags */
#define TASK_STKSZ 0  /* Stack size (use default one) */

RT_INTR intr_desc;

RT_TASK server_desc;

void irq_server (void *cookie)

{
    for (;;) {

       /* Wait for the next interrupt on channel #7. */
       err = rt_intr_wait(&intr_desc,TM_INFINITE);

       if (!err) {
           /* Process interrupt. */
       }
    }
}

int main (int argc, char *argv[])

{
    int err;

    mlockall(MCL_CURRENT|MCL_FUTURE);

    /* ... */

    err = rt_intr_create(&intr_desc,"MyIrq",IRQ_NUMBER,0);

    /* ... */

    err = rt_task_create(&server_desc,
			 "MyIrqServer",
			 TASK_STKSZ,
			 TASK_PRIO,
			 TASK_MODE);
    if (!err)
	rt_task_start(&server_desc,&irq_server,NULL);

    /* ... */
}

void cleanup (void)

{
    rt_intr_delete(&intr_desc);
    rt_task_delete(&server_desc);
}
