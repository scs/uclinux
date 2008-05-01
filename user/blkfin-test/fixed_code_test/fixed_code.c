/* Test each fixed code a ~million times */

#include <bfin_fixed_code.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

int num_iterations = 1000000;
#define fail(fmt, args...) fprintf(stderr, "FAIL: " fmt "\n", ## args)
#define failp(fmt, args...) fail(fmt ": %s", ## args, strerror(errno))
#define tfail(fmt, args...) fail(fmt, args), ++tret
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
		failp("vfork() failed");
}
static void bg_kill_busy(void)
{
	kill(busy, SIGTERM);
}

int test_xchg32(void)
{
	int cnt = num_iterations, tret = 0;
	unsigned int ret, base = rand(), swap = rand(), memory;
	while (--cnt) {
		memory = base;
		ret = bfin_atomic_xchg32(&memory, swap);
		if (ret != base || memory != swap)
			tfail("iter %i: (bfin_atomic_xchg32(%u, %u)=%u) != %u",
				cnt, base, swap, ret, memory);
	}
	return tret;
}

int test_cas32(void)
{
	int cnt = num_iterations, tret = 0;
	unsigned int ret, base = rand(), swap = rand(), memory;
	while (--cnt) {
		memory = base;
		ret = bfin_atomic_cas32(&memory, base, swap);
		if (ret != base || memory != swap)
			tfail("iter %i: (bfin_atomic_cas32(%u, %u, %u)=%u) != %u",
				cnt, base, base, swap, ret, memory);
	}
	return tret;
}

int test_add32(void)
{
	int cnt = num_iterations, tret = 0;
	unsigned int ret, base = rand(), inc = rand(), memory;
	while (--cnt) {
		memory = base;
		ret = bfin_atomic_add32(&memory, inc);
		if (ret != memory || ret != base + inc)
			tfail("iter %i: (bfin_atomic_add32(%u, %u)=%u) != %u",
				cnt, base, inc, ret, memory);
	}
	return tret;
}

int test_inc32(void)
{
	int cnt = num_iterations, tret = 0;
	unsigned int ret, base = rand(), memory;
	while (--cnt) {
		memory = base;
		ret = bfin_atomic_inc32(&memory);
		if (ret != memory || ret != base + 1)
			tfail("iter %i: (bfin_atomic_inc32(%u)=%u) != %u",
				cnt, base, ret, memory);
	}
	return tret;
}

int test_sub32(void)
{
	int cnt = num_iterations, tret = 0;
	unsigned int ret, base = rand(), dec = rand(), memory;
	while (--cnt) {
		memory = base;
		ret = bfin_atomic_sub32(&memory, dec);
		if (ret != memory || ret != base - dec)
			tfail("iter %i: (bfin_atomic_sub32(%u, %u)=%u) != %u",
				cnt, base, dec, ret, memory);
	}
	return tret;
}

int test_dec32(void)
{
	int cnt = num_iterations, tret = 0;
	unsigned int ret, base = rand(), memory;
	while (--cnt) {
		memory = base;
		ret = bfin_atomic_dec32(&memory);
		if (ret != memory || ret != base - 1)
			tfail("iter %i: (bfin_atomic_dec32(%u)=%u) != %u",
				cnt, base, ret, memory);
	}
	return tret;
}

int test_ior32(void)
{
	int cnt = num_iterations, tret = 0;
	unsigned int ret, base = rand(), bits = rand(), memory;
	while (--cnt) {
		memory = base;
		ret = bfin_atomic_ior32(&memory, bits);
		if (ret != memory || ret != (base | bits))
			tfail("iter %i: (bfin_atomic_ior32(%u, %u)=%u) != %u",
				cnt, base, bits, ret, memory);
	}
	return tret;
}

int test_and32(void)
{
	int cnt = num_iterations, tret = 0;
	unsigned int ret, base = rand(), bits = rand(), memory;
	while (--cnt) {
		memory = base;
		ret = bfin_atomic_and32(&memory, bits);
		if (ret != memory || ret != (base & bits))
			tfail("iter %i: (bfin_atomic_and32(%u, %u)=%u) != %u",
				cnt, base, bits, ret, memory);
	}
	return tret;
}

int test_xor32(void)
{
	int cnt = num_iterations, tret = 0;
	unsigned int ret, base = rand(), bits = rand(), memory;
	while (--cnt) {
		memory = base;
		ret = bfin_atomic_xor32(&memory, bits);
		if (ret != memory || ret != (base ^ bits))
			tfail("iter %i: (bfin_atomic_xor32(%u, %u)=%u) != %u",
				cnt, base, bits, ret, memory);
	}
	return tret;
}

int main(int argc, char *argv[])
{
	int ret;

	srand((unsigned long)(argv + time(0)));

	bg_launch_busy();

	ret += tcheck(test_xchg32);
	ret += tcheck(test_cas32);
	ret += tcheck(test_add32);
	ret += tcheck(test_inc32);
	ret += tcheck(test_sub32);
	ret += tcheck(test_dec32);
	ret += tcheck(test_ior32);
	ret += tcheck(test_and32);
	ret += tcheck(test_xor32);

	bg_kill_busy();

	return (ret ? EXIT_FAILURE : EXIT_SUCCESS);
}
