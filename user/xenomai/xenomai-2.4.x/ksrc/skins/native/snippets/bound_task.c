#include <sys/mman.h>
#include <native/task.h>

#define SIGNALS (0x1|0x4) /* Signals to send */

RT_TASK task_desc;

int main (int argc, char *argv[])

{
    int err;

    mlockall(MCL_CURRENT|MCL_FUTURE);

    /* Bind to a task which has been created elsewhere, either in
       kernel or user-space. The call will block us until such task is
       created with the expected name.  */

    err = rt_task_bind(&task_desc,"SomeTaskName",TM_NONBLOCK);

    if (!err)
	/* Send signals to the bound task */
	rt_task_notify(&task_desc,SIGNALS);

    /* ... */
}
