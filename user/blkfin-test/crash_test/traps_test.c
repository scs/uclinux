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

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(*x))

/* Single Step -                                       EXCAUSE 0x10 */
/* Can't do this in userspace */

/* Exception caused by a trace buffer full condition - EXCAUSE 0x11 */
/* Can't do this in userspace */

/* Undefined instruction -                             EXCAUSE 0x21 */
void unknown_instruction(void)
{
	asm(".word 0x0001;");
}

/* Illegal instruction combination -                   EXCAUSE 0x22 */

/* Data access CPLB protection violation -             EXCAUSE 0x23 */

/* Data access misaligned address violation -          EXCAUSE 0x24 */
void data_fetch_odd_address(void)
{
	int *i = (void *)0x87654321;
	printf("%i\n", *i);
}


/* Unrecoverable event -                               EXCAUSE 0x25 */
/* Can't do this in userspace (hopefully) */

/* Data access CPLB miss -                             EXCAUSE 0x26 */
void data_fetch_miss(void)
{
	int *i = (void *)0x87654320;
	printf("%i\n", *i);
}


/* Data access multiple CPLB hits -                    EXCAUSE 0x27 */
/* We use this to trap null pointers */
void null_pointer(void)
{
	int *i=0;
	*i=0;
}

/* Exception caused by an emulation watchpoint match - EXCAUSE 0x28 */
/* Can't do this in userspace */

/* Instruction fetch misaligned address violation -    EXCAUSE 0x2A */
void instruction_fetch_odd_address(void)
{
	int (*foo)(void);
	int i;
	i = (int)&instruction_fetch_odd_address;
	foo = (void *)(i+1);
	(*foo)();
}

/* Instruction fetch CPLB protection violation -       EXCAUSE 0x2B */

/* Instruction fetch CPLB miss -                       EXCAUSE 0x2C */
void instruction_fetch_miss(void)
{
	int (*foo)(void);
	int i;
	i=0x87654320;
	foo = (void *)i;
	(*foo)();
}

/* Instruction fetch multiple CPLB hits -              EXCAUSE 0x2C */
void jump_to_zero(void)
{
	int (*foo)(void);
	int i;
	i=0x0;
	foo = (void *)i;
	(*foo)();
}

/* Illegal use of supervisor resource -                EXCAUSE 0x2E */
void supervisor_instruction(void)
{
	asm("cli R0;");
}

void supervisor_resource_mmr(void)
{
	int *i=(void *)0xFFC00014;
	printf("chip id = %x", *i);

}
/* Things that cause Hardware errors (IRQ5), not exceptions (IRQ3) */
/* System MMR Error                                    HWERRCAUSE 0x02 */
/* Can't do this in userspace */

/* External Memory Addressing Error -                  HWERRCAUSE 0x03 */
void l1_instruction_access(void)
{
	int *i=(void *)0xffa10000;
	printf("%i\n", *i);
}

/* Performance Monitor Overflow                        HWERRCAUSE 0x012*/
/* Can't do this in userspace */

/* RAISE 5 instruction                                 HWERRCAUSE 0x18 */
/* Can't do this in userspace - since this is a supervisor instruction*/
void raise_5(void)
{
	asm("raise 0x05;");
}

/* Now for the main code */

struct {
	void (*func)(void);
	int kill_sig;
	char name[80];
} bad_funcs[] = {
	{ data_fetch_odd_address, SIGBUS, "Data access misaligned address violation" },
	{ data_fetch_miss, SIGBUS, "Data access CPLB miss" },
	{ null_pointer, SIGSEGV, "Data access multiple CPLB hits/Null Pointer" },
	{ instruction_fetch_odd_address, SIGBUS, "Instruction fetch misaligned address violation"  },
	{ instruction_fetch_miss, SIGBUS, "Instruction fetch CPLB miss"  },
	{ l1_instruction_access, SIGBUS, "l1_instruction_access" },
	{ supervisor_instruction, SIGILL, "Illegal use of supervisor resource - Instruction" },
	{ supervisor_resource_mmr, SIGBUS, "Illegal use of supervisor resource - MMR" },
	{ jump_to_zero, SIGSEGV, "Instruction fetch multiple CPLB hits - Jump to zero" },
	{ raise_5, SIGILL, "RAISE 5 instruction"},
	{ unknown_instruction, SIGILL, "Invalid Opcode" },
};

void usage(const char *errmsg)
{
	long test_num;

	printf(
		"Usage: bad_code [test number]\n"
		"\n"
		"If no test number is specified, the number of tests available will be shown.\n"
		"If a test number is specified (0 <= n < # of tests), that test will be run.\n"
		"If you specify -1, then all tests will be run in order.\n\n"
		"#\ttest\n"
	);
	for (test_num = 0; test_num < ARRAY_SIZE(bad_funcs); ++test_num)
		printf("%i\t%s\n", test_num, bad_funcs[test_num].name);

	if (errmsg) {
		fprintf(stderr, "\nERROR: %s\n", errmsg);
		exit(EXIT_FAILURE);
	} else
		exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	char *endptr;
	long test_num;

	if (argc == 1) {
		printf("%li\n", ARRAY_SIZE(bad_funcs) - 1);
		return EXIT_SUCCESS;
	}

	if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))
		usage(NULL);

	if (argc != 2)
		usage("Invalid number of arguments");

	test_num = strtol(argv[1], &endptr, 10);
	if (argv[1] == endptr || endptr[0])
		usage("Specified test is not a number");

	if (test_num >= 0 && test_num < ARRAY_SIZE(bad_funcs))
		/* should get killed ... */
		(*bad_funcs[test_num].func)();

	else if (test_num == -1) {
		int pass_count = 0;
		char number[10];
		argv[1] = number;

		for (test_num = 0; test_num < ARRAY_SIZE(bad_funcs); ++test_num) {
			pid_t pid;
			int status;

			sprintf(number, "%li", test_num);

			printf("Running test %li : %s\n... ", test_num, bad_funcs[test_num].name);
			fflush(stdout);

			pid = vfork();
			if (pid == 0) {
				int _ret;
				_ret = execv(argv[0], argv);
				fprintf(stderr, "Execution of '%s' failed (%i): %s\n",
					argv[0], _ret, strerror(errno));
				_exit(_ret);
			}

			wait(&status);
			if (WIFSIGNALED(status)) {
				int sig_expect = bad_funcs[test_num].kill_sig;
				int sig_actual = WTERMSIG(status);
				char *str_expect = strsignal(sig_expect);
				char *str_actual = strsignal(sig_actual);
				if (sig_expect == sig_actual) {
					printf("PASS (test failed as expected by signal %i: %s)\n",
						 sig_actual, str_actual);
					++pass_count;
				} else
					printf("FAIL (test failed, but not with the right signal)\n"
						"\t(We expected %i '%s' but instead we got %i '%s')\n",
						sig_expect, str_expect, sig_actual, str_actual);
			} else if (WIFEXITED(status))
				printf("FAIL (test incorrectly 'passed' by exiting with %i)\n",
					 WEXITSTATUS(status));
			else
				printf("FAIL (unknown exit status 0x%x)\n", status);

			fflush(stdout);
		}

		exit(pass_count == ARRAY_SIZE(bad_funcs) ? EXIT_SUCCESS : EXIT_FAILURE);

	} else
		usage("Test number out of range");

	/* should never actually make it here ... */
	return EXIT_FAILURE;
}
