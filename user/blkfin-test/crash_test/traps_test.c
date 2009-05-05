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

/*
 * These tests should test all things possible that can create an
 * exception. For details, look in arch/blackfin/mach-common/entry.S
 * in the kernel
 */

/* User Defined - Linux Syscall                        EXCAUSE 0x00 */
/* User Defined - Software breakpoint                  EXCAUSE 0x01 */
void expt_1(void)
{
	asm("excpt 0x1;");
}
/* User Defined - Should fail                          EXCAUSE 0x02 */
void expt_2(void)
{
	asm("excpt 0x2;");
}
/* User Defined - userspace stack overflow             EXCAUSE 0x03 */
void expt_3(void)
{
	asm("excpt 0x3;");
}
/* User Defined - dump trace buffer                    EXCAUSE 0x04 */
void expt_4(void)
{
	asm("excpt 0x4;");
}
/* User Defined - Should fail                          EXCAUSE 0x05 */
void expt_5(void)
{
	asm("excpt 0x5;");
}
/* User Defined - Should fail                          EXCAUSE 0x06 */
void expt_6(void)
{
	asm("excpt 0x6;");
}
/* User Defined - Should fail                          EXCAUSE 0x07 */
void expt_7(void)
{
	asm("excpt 0x7;");
}
/* User Defined - Should fail                          EXCAUSE 0x08 */
void expt_8(void)
{
	asm("excpt 0x8;");
}
/* User Defined - Should fail                          EXCAUSE 0x09 */
void expt_9(void)
{
	asm("excpt 0x9;");
}
/* User Defined - Should fail                          EXCAUSE 0x0A */
void expt_A(void)
{
	asm("excpt 0xA;");
}
/* User Defined - Should fail                          EXCAUSE 0x0B */
void expt_B(void)
{
	asm("excpt 0xB;");
}
/* User Defined - Should fail                          EXCAUSE 0x0C */
void expt_C(void)
{
	asm("excpt 0xC;");
}
/* User Defined - Should fail                          EXCAUSE 0x0D */
void expt_D(void)
{
	asm("excpt 0xD;");
}
/* User Defined - Should fail                          EXCAUSE 0x0E */
void expt_E(void)
{
	asm("excpt 0xE;");
}
/* User Defined - Should fail                          EXCAUSE 0x0F */
void expt_F(void)
{
	asm("excpt 0xF;");
}

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
void illegal_instruction(void)
{
	/* this relies on anomaly 05000074, but since that has applied to
	 * every Blackfin core and there are no plans on fixing it, it
	 * shouldn't be a problem.  these .long's expand into:
	 * R0 = R0 << 0x1 || [ P0 ] = P3 || NOP;
	 * thus avoiding the gas check on this combo
	 */
	asm(".long 0x8008ce82; .long 0x00009343;");
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

/* Exception caused by an emulation watchpoint match - EXCAUSE 0x28 */
/* Can't do this in userspace */

/* Instruction fetch misaligned address violation -    EXCAUSE 0x2A */
void instruction_fetch_odd_address(void)
{
	int (*foo)(void);
	int i;
	i = (int)&instruction_fetch_odd_address;
	foo = (void *)(i + 1);
	(*foo)();
}

/* Instruction fetch CPLB protection violation -       EXCAUSE 0x2B */

/* Instruction fetch CPLB miss -                       EXCAUSE 0x2C */
void instruction_fetch_miss(void)
{
	int (*foo)(void);
	int i;
	i = 0x87654320;
	foo = (void *)i;
	(*foo)();
}

/* Instruction fetch multiple CPLB hits -              EXCAUSE 0x2D */
void jump_to_zero(void)
{
	int (*foo)(void);
	foo = get_func_ptr(0);
	(*foo)();
}

/* Illegal use of supervisor resource -                EXCAUSE 0x2E */
void supervisor_instruction(void)
{
	asm("cli R0;");
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

void mmr_jump(void)
{
	int (*foo)(void);
	foo = get_func_ptr(0xFFC00014);
	(*foo)();
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
	{ 0x26, data_read_miss, SIGBUS, "Data Read CPLB miss" },
	{ 0x26, data_write_miss, SIGBUS, "Data Write CPLB miss" },
	{ 0x27, null_pointer_read, SIGSEGV, "Data access multiple CPLB hits/Null Pointer Read" },
	{ 0x27, null_pointer_write, SIGSEGV, "Data access multiple CPLB hits/Null Pointer Write" },
	{ 0x2a, instruction_fetch_odd_address, SIGBUS, "Instruction fetch misaligned address violation"  },
	{ 0x2c, instruction_fetch_miss, SIGBUS, "Instruction fetch CPLB miss"  },
	{ 0x2d, jump_to_zero, SIGSEGV, "Instruction fetch multiple CPLB hits - Jump to zero" },
	{ 0x2e, supervisor_instruction, SIGILL, "Illegal use of supervisor resource - Instruction" },
	{ 0x3f, l1_instruction_read, SIGBUS, "Read of L1 instruction" },
	{ 0x3f, l1_instruction_write, SIGBUS, "Write of L1 instruction" },
	{ 0x3f, l1_dataA_jump,  SIGBUS, "Jump to L1 Data A"},
	{ 0x3f, l1_dataB_jump,  SIGBUS, "Jump to L1 Data B"},
	{ 0x3f, l1_scratchpad_jump, SIGBUS, "Jump to L1 scratchpad"},
	{ 0x3f, mmr_jump, SIGBUS, "Jump to MMR Space"},
	{ 0x3f, l1_non_existant_jump, SIGBUS, "Jump to non-existant L1"},
	{ 0x3f, l1_non_existant_read, SIGBUS, "Read non-existant L1"},
	{ 0x3f, l1_non_existant_write, SIGBUS, "Write non-existant L1"},
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
		"#\texcause\ttest\n"
	);
	for (test_num = 0; test_num < ARRAY_SIZE(bad_funcs); ++test_num)
		printf("%li\t0x%02x\t%s\n", test_num, bad_funcs[test_num].excause, bad_funcs[test_num].name);

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

	if (test_num >= 0 && test_num < ARRAY_SIZE(bad_funcs)) {
		/* should get killed ... */
		printf("\nRunning test %li for exception 0x%02x: %s\n... ", test_num, bad_funcs[test_num].excause, bad_funcs[test_num].name);
		fflush(stdout);
		sleep(1);
		(*bad_funcs[test_num].func)();
	} else if (test_num == -1) {
		int pass_count = 0;
		char number[10];
		argv[1] = number;

		for (test_num = 0; test_num < ARRAY_SIZE(bad_funcs); ++test_num) {
			pid_t pid;
			int status;

			sprintf(number, "%li", test_num);

			pid = vfork();
			if (pid == 0) {
				int _ret = execvp(argv[0], argv);
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
                        sleep (1);
		}

		exit(pass_count == ARRAY_SIZE(bad_funcs) ? EXIT_SUCCESS : EXIT_FAILURE);

	} else
		usage("Test number out of range");

	/* should never actually make it here ... */
	return EXIT_FAILURE;
}
