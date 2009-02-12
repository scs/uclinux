#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <native/pipe.h>

#define PIPE_MINOR 0

/* User-space side */

int pipe_fd;

int main(int argc, char *argv[])
{
	char devname[32], buf[16];

	/* ... */

	sprintf(devname, "/dev/rtp%d", PIPE_MINOR);
	pipe_fd = open(devname, O_RDWR);

	if (pipe_fd < 0)
		fail();

	/* Wait for the prompt string "Hello"... */
	read(pipe_fd, buf, sizeof(buf));

	/* Then send the reply string "World": */
	write(pipe_fd, "World", sizeof("World"));

	/* ... */
}

void cleanup(void)
{
	close(pipe_fd);
}

/* Kernel-side */

#define TASK_PRIO  0		/* Highest RT priority */
#define TASK_MODE  T_FPU|T_CPU(0)	/* Uses FPU, bound to CPU #0 */
#define TASK_STKSZ 4096		/* Stack size (in bytes) */

RT_TASK task_desc;

RT_PIPE pipe_desc;

void task_body(void)
{
	RT_PIPE_MSG *msgout, *msgin;
	int err, len, n;

	for (;;) {
		/* ... */

		len = sizeof("Hello");
		/* Get a message block of the right size in order to
		   initiate the message-oriented dialog with the
		   user-space process. Sending a continuous stream of
		   bytes is also possible using rt_pipe_stream(), in
		   which case no message buffer needs to be
		   preallocated. */
		msgout = rt_pipe_alloc(len);

		if (!msgout)
			fail();

		/* Send prompt message "Hello" (the output buffer will be freed
		   automatically)... */
		strcpy(RT_PIPE_MSGPTR(msgout), "Hello");
		rt_pipe_send(&pipe_desc, msgout, len, P_NORMAL);

		/* Then wait for the reply string "World": */
		n = rt_pipe_receive(&pipe_desc, &msgin, TM_INFINITE);

		if (n < 0) {
			printf("receive error> errno=%d\n", n);
			continue;
		}
	
		if (n == 0) {
			if (msg == NULL) {
				printf("pipe closed by peer while reading\n");
				continue;
			}

			printf("empty message received\n");
		} else
			printf("received msg> %s, size=%d\n", P_MSGPTR(msg),
			       P_MSGSIZE(msg));

		/* Free the received message buffer. */
		rt_pipe_free(&pipe_desc, msgin);

		/* ... */
	}
}

init init_module(void)
{
	int err;

	err = rt_pipe_create(&pipe_desc, NULL, PIPE_MINOR);

	if (err)
		fail();

	/* ... */

	err = rt_task_create(&task_desc,
			     "MyTaskName", TASK_STKSZ, TASK_PRIO, TASK_MODE);
	if (!err)
		rt_task_start(&task_desc, &task_body, NULL);

	/* ... */
}

void cleanup_module(void)
{
	rt_pipe_delete(&pipe_desc);
	rt_task_delete(&task_desc);
}
