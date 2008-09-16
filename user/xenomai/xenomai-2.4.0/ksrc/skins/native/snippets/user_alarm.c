#include <sys/mman.h>
#include <native/task.h>
#include <native/alarm.h>

#define TASK_PRIO  99 /* Highest RT priority */
#define TASK_MODE  0  /* No flags */
#define TASK_STKSZ 0  /* Stack size (use default one) */

#define ALARM_VALUE    500000	/* First shot at now + 500 us */
#define ALARM_INTERVAL 250000	/* Period is 250 us */

RT_ALARM alarm_desc;

RT_TASK server_desc;

void alarm_server (void *cookie)

{
    for (;;) {

       /* Wait for the next alarm to trigger. */
       err = rt_alarm_wait(&alarm_desc);

       if (!err) {
           /* Process the alarm shot. */
       }
    }
}

int main (int argc, char *argv[])

{
    int err;

    mlockall(MCL_CURRENT|MCL_FUTURE);

    /* ... */

    err = rt_alarm_create(&alarm_desc,"MyAlarm");

    err = rt_alarm_start(&alarm_desc,
			 ALARM_VALUE,
			 ALARM_INTERVAL);
    /* ... */

    err = rt_task_create(&server_desc,
			 "MyAlarmServer",
			 TASK_STKSZ,
			 TASK_PRIO,
			 TASK_MODE);
    if (!err)
	rt_task_start(&server_desc,&alarm_server,NULL);

    /* ... */
}

void cleanup (void)

{
    rt_alarm_delete(&alarm_desc);
    rt_task_delete(&server_desc);
}
