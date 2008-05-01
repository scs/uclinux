/* Test each fixed code with threads */

/* TODO: implement tests for all funcs ... */

#include <bfin_fixed_code.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

const int num_iterations = 1000000, num_threads = 10;
#define fail(fmt, args...) fprintf(stderr, "FAIL: " fmt "\n", ##args)
#define failp(fmt, args...) fail(fmt ": %s", ##args, strerror(errno))
#define errp(fmt, args...) failp(fmt, ##args), exit(1)
#define tfail(fmt, args...) fail(fmt, ##args), ++tret
#define tcheck(func) \
({ \
	int __ret = func(); \
	if (__ret) \
		fail(#func); \
	else \
		puts("PASS: " #func); \
	__ret; \
})

pid_t busy;
static void bg_launch_busy(void)
{
	busy = vfork();
	if (busy == 0) {
		close(1);
		_exit(execlp("top", "top", "-d", "0", NULL));
	} else if (busy == -1)
		errp("vfork() failed");
}
static void bg_kill_busy(void)
{
	kill(busy, SIGTERM);
}

void ptest(void *func, void *arg)
{
	int t;
	pthread_t tid[num_threads];
	for (t = 0; t < num_threads; ++t)
		if (pthread_create(&tid[t], NULL, func, arg))
			errp("pthread_create() failed");
	void *status;
	for (t = 0; t < num_threads; ++t)
		if (pthread_join(tid[t], &status))
			errp("pthread_join() failed");
}

void *padd32(void *mem)
{
	int i;
	for (i = 0; i < num_iterations; ++i)
		bfin_atomic_add32(mem, 3);
	return 0;
}
int test_add32(void)
{
	unsigned int base = rand(), memory = base;
	ptest(padd32, &memory);
	return (memory == base + num_threads * num_iterations * 3 ? 0 : 1);
}

void *pinc32(void *mem)
{
	int i;
	for (i = 0; i < num_iterations; ++i)
		bfin_atomic_inc32(mem);
	return 0;
}
int test_inc32(void)
{
	unsigned int base = rand(), memory = base;
	ptest(pinc32, &memory);
	return (memory == base + num_threads * num_iterations ? 0 : 1);
}

void *psub32(void *mem)
{
	int i;
	for (i = 0; i < num_iterations; ++i)
		bfin_atomic_sub32(mem, 3);
	return 0;
}
int test_sub32(void)
{
	unsigned int base = rand(), memory = base;
	ptest(psub32, &memory);
	return (memory == base - num_threads * num_iterations * 3 ? 0 : 1);
}

void *pdec32(void *mem)
{
	int i;
	for (i = 0; i < num_iterations; ++i)
		bfin_atomic_dec32(mem);
	return 0;
}
int test_dec32(void)
{
	unsigned int base = rand(), memory = base;
	ptest(pdec32, &memory);
	return (memory == base - num_threads * num_iterations ? 0 : 1);
}

int main(int argc, char *argv[])
{
	int ret;

	srand((unsigned long)(argv + time(0)));

	bg_launch_busy();

//	ret += tcheck(test_xchg32);
//	ret += tcheck(test_cas32);
	ret += tcheck(test_add32);
	ret += tcheck(test_inc32);
	ret += tcheck(test_sub32);
	ret += tcheck(test_dec32);
//	ret += tcheck(test_ior32);
//	ret += tcheck(test_and32);
//	ret += tcheck(test_xor32);

	bg_kill_busy();

	return (ret ? EXIT_FAILURE : EXIT_SUCCESS);
}
