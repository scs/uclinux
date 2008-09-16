#include <stdio.h>
#include <sys/mman.h>
#include <native/task.h>
#include <rtdk.h>

void task2_func(void *arg)
{
	int i = 0;

	rt_printf("This triggers auto-init of rt_print for the "
		  "calling thread.\n"
		  "A last switch to secondary mode can occure here, "
		  "but future invocations of rt_printf are safe.\n");

	rt_task_set_mode(0, T_WARNSW, NULL);

	while (1) {
		rt_task_sleep(3333333LL);
		rt_fprintf(stderr, "%s: #%d Yet another RT printer - "
			   "but to stderr.\n", rt_print_buffer_name(), ++i);
	}
}

int main(int argc, char **argv)
{
	RT_TASK task1, task2;
	int i = 0;

	mlockall(MCL_CURRENT|MCL_FUTURE);

	/* Perform auto-init of rt_print buffers if the task doesn't do so */
	rt_print_auto_init(1);

	/* Initialise the rt_print buffer for this task explicitly */
	rt_print_init(4096, "Task 1");

	rt_task_shadow(&task1, "Task 1", 10, 0);
	rt_task_spawn(&task2, "Task 2", 0, 11, 0, task2_func, NULL);

	/* To demonstrate that rt_printf is safe */
	rt_task_set_mode(0, T_WARNSW, NULL);

	while (1) {
		rt_task_sleep(5000000LL);
		rt_printf("%s: #%d Hello RT world!\n",
			  rt_print_buffer_name(), ++i);
	}
}
