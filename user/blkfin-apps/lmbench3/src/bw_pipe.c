/*
 * bw_pipe.c - pipe bandwidth benchmark.
 *
 * Usage: bw_pipe [-m <message size>] [-M <total bytes>] \
 *		[-P <parallelism>] [-W <warmup>] [-N <repetitions>]
 *
 * Copyright (c) 1994 Larry McVoy.  
 * Copyright (c) 2002 Carl Staelin.
 * Distributed under the FSF GPL with additional restriction that results 
 * may published only if:
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 * Support for this development by Sun Microsystems is gratefully acknowledged.
 */
char	*id = "$Id: bw_pipe.c 1581 2005-11-24 08:26:31Z sonicz $\n";

#include "bench.h"

void	reader(iter_t iterations, void* cookie);
void	writer(int writefd, char* buf, size_t xfer);

int	XFER	= 10*1024*1024;

struct _state {
	int	pid;
	size_t	xfer;	/* bytes to read/write per "packet" */
	size_t	bytes;	/* bytes to read/write in one iteration */
	char	*buf;	/* buffer memory space */
	int	readfd;
	int	initerr;
};

#ifdef CONFIG_NOMMU
struct bw_pipe_thread_data {
	char		stack[STACK_SIZE];
	int		pipes[2];
	struct _state*	state;
};

static struct bw_pipe_thread_data thda;

int
bw_pipe_thread_function(void *t)
{
	struct bw_pipe_thread_data *pthd = (struct bw_pipe_thread_data *)t;
	close(pthd->pipes[0]);
	handle_scheduler(benchmp_childid(), 1, 1);
	pthd->state->buf = valloc(pthd->state->xfer);
	if (pthd->state->buf == NULL) {
		perror("child: no memory");
		pthd->state->initerr = 4;
		return 0;
	}
	touch(pthd->state->buf, pthd->state->xfer);
	writer(pthd->pipes[1], pthd->state->buf, pthd->state->xfer);
	return 0;
}
#endif

void
initialize(iter_t iterations, void *cookie)
{
	int	pipes[2];
	struct _state* state = (struct _state*)cookie;

	if (iterations) return;

	state->initerr = 0;
	if (pipe(pipes) == -1) {
		perror("pipe");
		state->initerr = 1;
		return;
	}
	handle_scheduler(benchmp_childid(), 0, 1);
#ifdef CONFIG_NOMMU
	thda.pipes[0] = pipes[0];
	thda.pipes[1] = pipes[1];
	thda.state = state;
	state->pid = clone(bw_pipe_thread_function, thda.stack + STACK_SIZE - 4, CLONE_VM|SIGCHLD, &thda);
#else
	switch (state->pid = fork()) {
	    case 0:
		close(pipes[0]);
		handle_scheduler(benchmp_childid(), 1, 1);
		state->buf = valloc(state->xfer);
		if (state->buf == NULL) {
			perror("child: no memory");
			state->initerr = 4;
			return;
		}
		touch(state->buf, state->xfer);
		writer(pipes[1], state->buf, state->xfer);
		return;
		/*NOTREACHED*/
	    
	    case -1:
		perror("fork");
		state->initerr = 3;
		return;
		/*NOTREACHED*/

	    default:
		break;
	}
#endif
	close(pipes[1]);
	state->readfd = pipes[0];
	state->buf = valloc(state->xfer + getpagesize());
	if (state->buf == NULL) {
		perror("parent: no memory");
		state->initerr = 4;
		return;
	}
	touch(state->buf, state->xfer + getpagesize());
	state->buf += 128; /* destroy page alignment */
}

void
cleanup(iter_t iterations, void * cookie)
{
	struct _state* state = (struct _state*)cookie;

	if (iterations) return;

	close(state->readfd);
	if (state->pid > 0) {
		kill(state->pid, SIGKILL);
		waitpid(state->pid, NULL, 0);
	}
	state->pid = 0;
}

void
reader(iter_t iterations, void * cookie)
{
	size_t	done;
	ssize_t	n;
	struct _state* state = (struct _state*)cookie;

	while (iterations-- > 0) {
		for (done = 0; done < state->bytes; done += n) {
			if ((n = read(state->readfd, state->buf, state->xfer)) < 0) {
				perror("bw_pipe: reader: error in read");
				exit(1);
			}
		}
	}
}

void
writer(int writefd, char* buf, size_t xfer)
{
	size_t	done;
	ssize_t	n;

	for ( ;; ) {
#ifdef TOUCH
		touch(buf, xfer);
#endif
		for (done = 0; done < xfer; done += n) {
			if ((n = write(writefd, buf, xfer - done)) < 0) {
				exit(0);
			}
		}
	}
}

int
main(int ac, char *av[])
{
	struct _state state;
	int parallel = 1;
	int warmup = 0;
	int repetitions = TRIES;
	int c;
	char* usage = "[-m <message size>] [-M <total bytes>] [-P <parallelism>] [-W <warmup>] [-N <repetitions>]\n";

	state.xfer = XFERSIZE;	/* per-packet size */
	state.bytes = XFER;	/* total bytes per call */

	while (( c = getopt(ac, av, "m:M:P:W:N:")) != EOF) {
		switch(c) {
		case 'm':
			state.xfer = bytes(optarg);
			break;
		case 'M':
			state.bytes = bytes(optarg);
			break;
		case 'P':
			parallel = atoi(optarg);
			if (parallel <= 0) lmbench_usage(ac, av, usage);
			break;
		case 'W':
			warmup = atoi(optarg);
			break;
		case 'N':
			repetitions = atoi(optarg);
			break;
		default:
			lmbench_usage(ac, av, usage);
			break;
		}
	}
	if (optind < ac) {
		lmbench_usage(ac, av, usage);
	}
	/* round up total byte count to a multiple of xfer */
	if (state.bytes < state.xfer) {
		state.bytes = state.xfer;
	} else if (state.bytes % state.xfer) {
		state.bytes += state.bytes - state.bytes % state.xfer;
	}
	benchmp(initialize, reader, cleanup, MEDIUM, parallel, 
		warmup, repetitions, &state);

	if (gettime() > 0) {
		fprintf(stderr, "Pipe bandwidth: ");
		mb(get_n() * parallel * state.bytes);
	}
	return(0);
}
