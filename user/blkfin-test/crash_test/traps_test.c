/****************************************************************************
 * This application tries to cause one of every type of fault event that the
 * Blackfin processor can or can not handle, in order to test the kernel's
 * exception handler's robustness, and ability to recover from a userspace
 * fault condition properly.
 *
 * This is all bad bad code - you should not look at this as examples for
 * anything (unless you want to also test the kernel's robustness). If you
 * can find something that the kernel does not respond well to, please add
 * it to this list.
 *
 **********************************************************************
 * Copyright Analog Devices Inc 2007
 * Released under the GPL 2 or later
 *
 ***************************************************************************/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef __FDPIC__
# define _get_func_ptr(addr) ({ unsigned long __addr[2] = { addr, 0 }; __addr; })
#else
# define _get_func_ptr(addr) (addr)
#endif
#define get_func_ptr(addr) (void *)(_get_func_ptr(addr))

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(*x))

void _bad_return_address(unsigned long rets);
asm("__bad_return_address: rets = R0; nop; nop; nop; nop; rts;\n");

void _bad_stack_set(unsigned long rets);
asm("__bad_stack_set: SP = R0; FP = R0; nop; nop; rts;\n");

#define bad_stack_push(addr)	asm volatile ("R1 = SP ; SP = %0; [SP] = %0; SP = R1" :  : "r"(addr) : "R1" );

/*
 * These tests should test all things possible that can create an
 * exception. For details, look in arch/blackfin/mach-common/entry.S
 * in the kernel
 */

/* User Defined - Linux Syscall                        EXCAUSE 0x00 */
/* User Defined - Software breakpoint                  EXCAUSE 0x01 */
void expt_1(void)
{
	asm volatile("excpt 0x1;");
}
/* User Defined - Should fail                          EXCAUSE 0x02 */
void expt_2(void)
{
	asm volatile("excpt 0x2;");
}
/* User Defined - userspace stack overflow             EXCAUSE 0x03 */
void expt_3(void)
{
	asm volatile("excpt 0x3;");
}
/* User Defined - dump trace buffer                    EXCAUSE 0x04 */
void expt_4(void)
{
	asm volatile("excpt 0x4;");
}
/* User Defined - Should fail                          EXCAUSE 0x05 */
void expt_5(void)
{
	asm volatile("excpt 0x5;");
}
/* User Defined - Should fail                          EXCAUSE 0x06 */
void expt_6(void)
{
	asm volatile("excpt 0x6;");
}
/* User Defined - Should fail                          EXCAUSE 0x07 */
void expt_7(void)
{
	asm volatile("excpt 0x7;");
}
/* User Defined - Should fail                          EXCAUSE 0x08 */
void expt_8(void)
{
	asm volatile("excpt 0x8;");
}
/* User Defined - Should fail                          EXCAUSE 0x09 */
void expt_9(void)
{
	asm volatile("excpt 0x9;");
}
/* User Defined - Should fail                          EXCAUSE 0x0A */
void expt_A(void)
{
	asm volatile("excpt 0xA;");
}
/* User Defined - Should fail                          EXCAUSE 0x0B */
void expt_B(void)
{
	asm volatile("excpt 0xB;");
}
/* User Defined - Should fail                          EXCAUSE 0x0C */
void expt_C(void)
{
	asm volatile("excpt 0xC;");
}
/* User Defined - Should fail                          EXCAUSE 0x0D */
void expt_D(void)
{
	asm volatile("excpt 0xD;");
}
/* User Defined - Should fail                          EXCAUSE 0x0E */
void expt_E(void)
{
	asm volatile("excpt 0xE;");
}
/* User Defined - Should fail                          EXCAUSE 0x0F */
void expt_F(void)
{
	asm volatile("excpt 0xF;");
}

/* Single Step -                                       EXCAUSE 0x10 */
/* Can't do this in userspace */

/* Exception caused by a trace buffer full condition - EXCAUSE 0x11 */
/* Can't do this in userspace */

/* Undefined instruction -                             EXCAUSE 0x21 */
void unknown_instruction(void)
{
	asm volatile(".word 0x0001;");
}

/* Illegal instruction combination -                   EXCAUSE 0x22 */
void illegal_instruction(void)
{
	/* this relies on anomaly 05000074, but since that has applied to
	 * every Blackfin core and there are no plans on fixing it, it
	 * shouldn't be a problem.  these .long's expand into:
	 * R0 = R0 << 0x1 || [ P0 ] = P3 || NOP;
	 * thus avoiding the gas check on this combo
	 */
	asm volatile(".long 0x8008ce82; .long 0x00009343;");
}

/* Data access CPLB protection violation -             EXCAUSE 0x23 */

/* Data access misaligned address violation -          EXCAUSE 0x24 */
void data_read_odd_address(void)
{
	int *i = (void *)0x87654321;
	printf("%i\n", *i);
}

void data_write_odd_address(void)
{
	int *i = (void *)0x87654321;
	*i = 0;
}

void stack_odd_address(void)
{
	_bad_stack_set(0x87654321);
}

void stack_push_odd_address(void)
{
	bad_stack_push(0x87654321);
}

/* Unrecoverable event -                               EXCAUSE 0x25 */
/* Can't do this in userspace (hopefully) */

/* Data access CPLB miss -                             EXCAUSE 0x26 */
void data_read_miss(void)
{
	int *i = (void *)0x87654320;
	printf("%i\n", *i);
}

void data_write_miss(void)
{
	int *i = (void *)0x87654320;
	*i = 0;
}

void stack_miss(void)
{
        _bad_stack_set(0x87654320);
}

void stack_push_miss(void)
{
	bad_stack_push(0x87654320);
}

/* Data access multiple CPLB hits -                    EXCAUSE 0x27 */
/* We use this to trap null pointers */
void null_pointer_write(void)
{
	int *i = 0;
	*i = 0;
}

void null_pointer_read(void)
{
	int *i = 0;
	printf("%i", *i);
}

void stack_zero(void)
{
        _bad_stack_set(0x0);
}

void stack_push_zero(void)
{
	bad_stack_push(0);
}

/* Exception caused by an emulation watchpoint match - EXCAUSE 0x28 */
/* Can't do this in userspace */

/* Instruction fetch misaligned address violation -    EXCAUSE 0x2A */
void instruction_fetch_odd_address(void)
{
	int (*foo)(void);
	foo = get_func_ptr((int)&instruction_fetch_odd_address + 1);
	(*foo)();
}

/* Instruction fetch CPLB protection violation -       EXCAUSE 0x2B 
 * with mpu on, these return 2B, otherwise
 */
void bad_return_scratchpad(void)
{
	_bad_return_address(0xFFB00000);
}

void bad_return_l1dataA(void)
{
	_bad_return_address(0xFF800000);
}

void bad_return_l1dataB(void)
{
	_bad_return_address(0xFF900000);
}

/* Instruction fetch CPLB miss -                       EXCAUSE 0x2C */
void instruction_fetch_miss(void)
{
	int (*foo)(void);
	foo = get_func_ptr(0x87654320);
	(*foo)();
}

void bad_return_bad_location(void)
{
	_bad_return_address(0x87654320);
}

void mmr_jump(void)
{
	int (*foo)(void);
	foo = get_func_ptr(0xFFC00014);
	(*foo)();
}

/* Instruction fetch multiple CPLB hits -              EXCAUSE 0x2D */
void jump_to_zero(void)
{
	int (*foo)(void);
	foo = get_func_ptr(0);
	(*foo)();
}

void bad_return_zero(void)
{
	_bad_return_address(0x0);
}

/* Illegal use of supervisor resource -                EXCAUSE 0x2E */
void supervisor_instruction(void)
{
	asm volatile("cli R0;");
}

void supervisor_resource_mmr_read(void)
{
	int *i = (void *)0xFFC00014;
	printf("chip id = %x", *i);

}

void supervisor_resource_mmr_write(void)
{
	int *i = (void *)0xFFC00014;
	*i = 0;
}

/* Things that cause Hardware errors (IRQ5), not exceptions (IRQ3) */
/* System MMR Error                                    HWERRCAUSE 0x02 */
/* Can't do this in userspace */

/* External Memory Addressing Error -                  HWERRCAUSE 0x03 */
//__attribute__ ((l1_text))
void l1_instruction_read(void)
{
	int *i = (void *)0xffa10000;
	printf("%i\n", *i);
}

void l1_instruction_write(void)
{
	int *i = (void *)0xffa10000;
	*i = 0;
}

void stack_instruction(void)
{
        _bad_stack_set(0xffa10000);
}

void l1_dataA_jump(void)
{
	int (*foo)(void);
	foo = get_func_ptr(0xFF800000);
	(*foo)();
}

void l1_dataB_jump(void)
{
	int (*foo)(void);
	foo = get_func_ptr(0xFF900000);
	(*foo)();
}

void l1_scratchpad_jump(void)
{
	int (*foo)(void);
	foo = get_func_ptr(0xFFB00000);
	(*foo)();
}

void l1_non_existant_jump(void)
{
	int (*foo)(void);
	foo = get_func_ptr(0xFFAFFFFC);
	(*foo)();
}

void l1_non_existant_read(void)
{
	int *i = (void *)0xFFAFFFFC;
	printf("%i\n", *i);
}

void l1_non_existant_write(void)
{
	int *i = (void *)0xFFAFFFFC;
	*i = 0;
}

void stack_l1_non_existant(void)
{
        _bad_stack_set(0xFFAFFF00);
}

void stack_push_l1_non_existant(void)
{
	bad_stack_push(0xFFAFFF00);
}

void bad_return_l1_non_existant(void)
{
	_bad_return_address(0xFFAFFFFC);
}

void bad_return_mmr(void)
{
	_bad_return_address(0xFFC00014);
}

/* Performance Monitor Overflow                        HWERRCAUSE 0x012*/
/* Can't do this in userspace */

/* RAISE 5 instruction                                 HWERRCAUSE 0x18 */
/* Can't do this in userspace - since this is a supervisor instruction */

/* Now for the main code */

struct {
	int excause;
	void (*func)(void);
	int kill_sig;
	const char *name;
} bad_funcs[] = {
	{ 0x01, expt_1, SIGTRAP, "EXCPT 0x01" },
	{ 0x02, expt_2, SIGILL, "EXCPT 0x02" },
	{ 0x03, expt_3, SIGSEGV, "EXCPT 0x03" },
	{ 0x04, expt_4, SIGILL, "EXCPT 0x04" },
	{ 0x05, expt_5, SIGILL, "EXCPT 0x05" },
	{ 0x06, expt_6, SIGILL, "EXCPT 0x06" },
	{ 0x07, expt_7, SIGILL, "EXCPT 0x07" },
	{ 0x08, expt_8, SIGILL, "EXCPT 0x08" },
	{ 0x09, expt_9, SIGILL, "EXCPT 0x09" },
	{ 0x0A, expt_A, SIGILL, "EXCPT 0x0A" },
	{ 0x0B, expt_B, SIGILL, "EXCPT 0x0B" },
	{ 0x0C, expt_C, SIGILL, "EXCPT 0x0C" },
	{ 0x0D, expt_D, SIGILL, "EXCPT 0x0D" },
	{ 0x0E, expt_E, SIGILL, "EXCPT 0x0E" },
	{ 0x0F, expt_F, SIGILL, "EXCPT 0x0F" },
	{ 0x21, unknown_instruction, SIGILL, "Invalid Opcode" },
	{ 0x22, illegal_instruction, SIGILL, "Illegal Instruction" },
	{ 0x23, supervisor_resource_mmr_read, SIGBUS, "Illegal use of supervisor resource - MMR Read" },
	{ 0x23, supervisor_resource_mmr_write, SIGBUS, "Illegal use of supervisor resource - MMR Write" },
	{ 0x24, data_read_odd_address, SIGBUS, "Data read misaligned address violation" },
	{ 0x24, data_write_odd_address, SIGBUS, "Data write misaligned address violation" },
	{ 0x24, stack_odd_address, SIGBUS, "Stack set to odd address - misaligned address violation" },
	{ 0x24, stack_push_odd_address, SIGBUS, "Stack push to odd address" },
	{ 0x26, data_read_miss, SIGBUS, "Data Read CPLB miss" },
	{ 0x26, data_write_miss, SIGBUS, "Data Write CPLB miss" },
	{ 0x26, stack_miss, SIGBUS, "Stack CPLB miss" },
	{ 0x26, stack_push_miss, SIGBUS, "Stack push to miss" },
	{ 0x27, null_pointer_read, SIGSEGV, "Data access multiple CPLB hits/Null Pointer Read" },
	{ 0x27, null_pointer_write, SIGSEGV, "Data access multiple CPLB hits/Null Pointer Write" },
	{ 0x27, stack_zero, SIGSEGV, "Stack set to zero" },
	{ 0x27, stack_push_zero, SIGSEGV, "Stack, push while SP is zero" },
	{ 0x2a, instruction_fetch_odd_address, SIGBUS, "Instruction fetch misaligned address violation"  },
	{ 0x2b, l1_dataA_jump,  SIGBUS, "Jump to L1 Data A" },
	{ 0x2b, bad_return_l1dataA, SIGBUS, "Return to L1 Data A" },
	{ 0x2b, l1_dataB_jump,  SIGBUS, "Jump to L1 Data B" },
	{ 0x2b, bad_return_l1dataB, SIGBUS, "Return to L1 Data B" },
	{ 0x2b, l1_scratchpad_jump, SIGBUS, "Jump to L1 scratchpad" },
	{ 0x2b, bad_return_scratchpad, SIGBUS, "Return to scratchpad" },
	{ 0x2c, instruction_fetch_miss, SIGBUS, "Instruction fetch CPLB miss"  },
	{ 0x2c, mmr_jump, SIGBUS, "Jump to MMR Space" },
	{ 0x2c, bad_return_bad_location, SIGBUS, "Return to non-existant L3" },
	{ 0x2c, bad_return_mmr, SIGBUS, "Return to an MMR address" },
	{ 0x2d, jump_to_zero, SIGSEGV, "Instruction fetch multiple CPLB hits - Jump to zero" },
	{ 0x2d, bad_return_zero, SIGSEGV, "Return to zero" },
	{ 0x2e, supervisor_instruction, SIGILL, "Illegal use of supervisor resource - Instruction" },
	{ 0x3f, l1_instruction_read, SIGBUS, "Read of L1 instruction" },
	{ 0x3f, l1_instruction_write, SIGBUS, "Write of L1 instruction" },
	{ 0x3f, l1_non_existant_jump, SIGBUS, "Jump to non-existant L1" },
	{ 0x3f, l1_non_existant_read, SIGBUS, "Read non-existant L1" },
	{ 0x3f, l1_non_existant_write, SIGBUS, "Write non-existant L1" },
	{ 0x3f, bad_return_l1_non_existant, SIGBUS, "Return to non-existant L1" },
	{ 0x3f, stack_instruction, SIGBUS, "Stack set to L1 instruction" },
	{ 0x3f, stack_l1_non_existant, SIGBUS, "Stack set to non-existant L1" },
	{ 0x3f, stack_push_l1_non_existant, SIGBUS, "Stack push to non-existant L1" },
};

void list_tests(void)
{
	long test_num;

	printf("#\texcause\ttest\n");
	for (test_num = 0; test_num < ARRAY_SIZE(bad_funcs); ++test_num)
		printf("%li\t0x%02x\t%s\n", test_num, bad_funcs[test_num].excause, bad_funcs[test_num].name);

	exit(EXIT_SUCCESS);
}

void usage(const char *errmsg, char *progname)
{
	printf(
		"Usage: %s [-c count] [-d milliseconds] [-q] [-l] [test number]\n"
		"\n"
		"-c count\tRepeat the test(s) count times before stopping\n"
		"-d seconds\tThe number of milliseconds to delay between flushing stdout, and\n"
		"\t\trunning the test (default is 1)\n"
		"-l\t\tList tests, then quit\n"
		"-q\t\tQuiet (don't print out test info)\n"
		"If no test number is specified, the number of tests available will be shown.\n"
		"If a test number is specified (0 <= n < # of tests), that test will be run.\n"
		"If you specify -1, then all tests will be run in order.\n\n", progname
	);

	if (errmsg) {
		fprintf(stderr, "\nERROR: %s\n", errmsg);
		exit(EXIT_FAILURE);
	} else
		exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	char *endptr;
	long test_num = 0;
	int c, repeat = 1, count = 1, del;
	int pass_count = 0, quiet = 0;
	struct timespec delay;

	delay.tv_sec = 1;
	delay.tv_nsec = 0;
	del = 1000;

	if (argc == 1) {
		printf("%li\n", ARRAY_SIZE(bad_funcs) - 1);
		return EXIT_SUCCESS;
	}

	while ((c = getopt (argc, argv, "1c:d:hlq")) != -1)
		switch (c)
		{
		case '1':
			test_num = -1;
			break;
		case 'c':
			repeat = strtol(optarg, &endptr, 10);
			if (optarg == endptr || endptr[0] || repeat <= 0)
				usage("did not understand count", argv[0]);
			break;
		case 'h':
			usage(NULL, argv[0]);
			break;
		case 'd':
			del = strtol(optarg, &endptr, 10);
			if (optarg == endptr || endptr[0])
				usage("did not understand delay", argv[0]);
			/* get seconds & nanoseconds */
			delay.tv_sec = del / 1000;
			delay.tv_nsec = (del - (delay.tv_sec * 1000)) * 1000000;
			break;
		case 'l':
			list_tests();
			break;
		case 'q':
			quiet = 1;
			break;
		case '?':
		default:
			usage("unknown option", argv[0]);
			break;
		}

	if (optind == argc && test_num != -1)
		usage(NULL, argv[0]);

	if (test_num != -1)
		test_num = strtol(argv[optind], &endptr, 10);

	if ((argv[optind] == endptr || endptr[0]) && test_num != -1)
		usage("Specified test is not a number", argv[0]);

	if (test_num >= 0 && test_num < ARRAY_SIZE(bad_funcs)) {
		int sig_actual=0;
		char *str_actual;

		if (!quiet) {
			printf("\nRunning test %li for exception 0x%02x: %s\n... ", test_num, bad_funcs[test_num].excause, bad_funcs[test_num].name);
			fflush(stdout);
		}
		nanosleep(&delay, NULL);

		/* should get killed ... */
		if (repeat == 1)
			(*bad_funcs[test_num].func)();

		count = repeat;
		while (count) {
			pid_t pid;
			int status;

			count--;

			pid = vfork();
			if (pid == 0) {
				int _ret = execlp(argv[0], argv[0], "-d", "0", "-q", argv[optind], NULL);
				fprintf(stderr, "Execution of '%s' failed (%i): %s\n",
					argv[0], _ret, strerror(errno));
				_exit(_ret);
			}

			wait(&status);
			if (WIFSIGNALED(status)) {
				int sig_expect = bad_funcs[test_num].kill_sig;
				sig_actual = WTERMSIG(status);
				if (sig_expect == sig_actual) {
					++pass_count;
				} else {
					char *str_expect = strsignal(sig_expect);
					str_actual = strsignal(sig_actual);
					printf("FAIL (test failed, but not with the right signal)\n"
						"\t(We expected %i '%s' but instead we got %i '%s')\n",
						sig_expect, str_expect, sig_actual, str_actual);
					exit(EXIT_FAILURE);
				}
			}
		}
		str_actual = strsignal(sig_actual);
		printf("PASS (test failed %i times, as expected by signal %i: %s)\n",
			pass_count, sig_actual, str_actual);
		exit(EXIT_SUCCESS);
	} else if (test_num == -1) {
		char number[10];
		char pause[10];
		char cnt[10];
		argv[1] = number;

		for (test_num = 0; test_num < ARRAY_SIZE(bad_funcs); ++test_num) {
			pid_t pid;
			int status;

			sprintf(number, "%li", test_num);
			sprintf(pause, "%i", del);
			sprintf(cnt, "%i", repeat);

			pid = vfork();
			if (pid == 0) {
				int _ret = execlp(argv[0], argv[0], "-d", pause, "-c", cnt, number, NULL);
				fprintf(stderr, "Execution of '%s' failed (%i): %s\n",
					argv[0], _ret, strerror(errno));
				_exit(_ret);
			}

			wait(&status);
			if (WIFSIGNALED(status)) {
				int sig_actual = WTERMSIG(status);
				char *str_actual = strsignal(sig_actual);
				printf("Test application issue: received signal %i, (%s)\n", sig_actual, str_actual);
				exit(EXIT_FAILURE);
			} else if (WIFEXITED(status)) {
				if (WEXITSTATUS(status) == EXIT_SUCCESS)
					++pass_count;
			} else
				printf("FAIL (unknown exit status 0x%x)\n", status);

		}

		exit(pass_count == ARRAY_SIZE(bad_funcs) ? EXIT_SUCCESS : EXIT_FAILURE);

	} else
		usage("Test number out of range", argv[0]);

	/* should never actually make it here ... */
	return EXIT_FAILURE;
}
