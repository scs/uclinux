// ****************************************************************************
// *** (c) Copyright 2003 Analog Devices  Corporations                      ***
// ***                                                                      ***
// *** Analog Devices Confidential & Sensitive. All Rights Reserved.        ***
// ***                                                                      ***
// *** No part of this file may be modified or reproduced without explicit  ***
// *** consent from Analog Devices Corporations.                            ***
// ***                                                                      ***
// *** All information contained in this file is subject to change without  ***
// *** notice.                                                              ***
// ***                                                                      ***
// *** Description: This file contains all codec calling functions          ***
// ***              illustrate how to use the encoder/decoder               ***
// ****************************************************************************

/*
  729ab_test.c
  David Rowe (contractor to Analog Devices)
  9 October 2006

  Test program for G729AB code optimised for blackfin.uclinux.  Derived from
  earlier test programs such as g729_test.c g729_test_ab.c.  This version
  can test both G729A (reduced complexity G729) and G729AB (reduced compelxity
  G729 with VAD).
*/

#include "g729ab_codec.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#ifdef DLOPEN
#include <dlfcn.h>
#endif

#define FRAMES_PER_SEC 100	/* 10ms frames */
#define MAX_THREADS    20
#define NUM_ENC        2
#define NUM_DEC        2

/* structure used to pass command line args to threads */

typedef struct {
	int argc;
	char **argv;
} ARGS;

struct my_args {
	ARGS *args;
	int thread_id;
};

int active_threads;
pthread_mutex_t active_threads_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t thread[MAX_THREADS];

/* C-callable function to return value of CYCLES register */

unsigned int cycles(void)
{
	int ret;
	__asm__ __volatile__("%0 = CYCLES;" : "=&d"(ret));
	return ret;
}

int fread_a_frame(FILE * file, short *frame)
{
	short read_short = 0;
	short read_len = 0;
	int ret = 0;
	short *tmp = frame;

	ret = fread(&read_short, 2, 1, file);
	if (ret < 1)
		return -1;
	if (read_short == 0x6b21) {

		*tmp++ = read_short;
		ret = fread(&read_short, 2, 1, file);
		if (ret < 1)
			return -1;

		/* Get length */
		*tmp++ = read_short;
		if (read_short == 0) {
			return 0;
		} else {

			read_len = fread(tmp, 2, read_short, file);
			if (read_len != read_short)
				return -1;
			else
				return read_short;
		}
	} else {

		fprintf(stderr, "wrong header: 0x%hx\n", read_short);
		return -2;
	}

	return -1;
}

int test_encoder(int mode, FILE * fin, FILE * fbit, float *av_mips, int multi,
		 int thread_id)
{
	G729_EncObj inst_g729_enc __attribute__ ((aligned(4)));
	G729_enc_h inst_g729_enc_h __attribute__ ((aligned(4)));

	short inst_pcm_buf[80] __attribute__ ((aligned(4)));
	short inst_index_buf[82] __attribute__ ((aligned(4)));
	short result_buf[82];

	int frame_num = 0;
	int i = 0;
	int len;
	int before, time;

	memset(&inst_pcm_buf, 80 * 2, 0);
	memset(&inst_index_buf, 82 * 2, 0);

	/* Init encoder */

	inst_g729_enc_h = &inst_g729_enc;
	(*g729ab_enc_reset) (inst_g729_enc_h);
	G729AB_ENC_CONFIG(inst_g729_enc_h, G729_ENC_OUTPUTFORMAT, 1);
	G729AB_ENC_CONFIG(inst_g729_enc_h, G729_ENC_VAD, mode);

	time = 0;
	while ((fread(inst_pcm_buf, 2, 80, fin) == 80)) {
		//fprintf(stderr, "thread: %d - frame: %d\n", thread_id, frame_num);
		before = cycles();
		G729AB_ENC(inst_g729_enc_h, inst_pcm_buf, inst_index_buf);
		time += cycles() - before;

		/* simulate "hurry up and wait" of real time systems when
		   testing in multi-threaded mode */

		if (multi)
			usleep(10000);

		/* Verify */

		if (mode)
			len = fread_a_frame(fbit, result_buf);
		else
			len = fread(result_buf, sizeof(short), 82, fbit);

		for (i = 0; i < len; ++i) {
			if (result_buf[i] != inst_index_buf[i]) {
				fprintf(stderr, "diff:%d %hx, %hx\n",
					frame_num * 82 + i, inst_index_buf[i],
					result_buf[i]);
				return -1;
			}
		}

		frame_num++;
	}

	*av_mips = (float)(time / frame_num) * (FRAMES_PER_SEC / 1E6);

	return 0;
}

int test_decoder(int mode, FILE * fbit, FILE * fout, float *av_mips, int multi,
		 int thread_id)
{
	G729_DecObj inst_g729_dec __attribute__ ((aligned(4)));
	G729_dec_h inst_g729_dec_h __attribute__ ((aligned(4)));

	short inst_pcm_buf[80] __attribute__ ((aligned(4)));
	short inst_index_buf[82] __attribute__ ((aligned(4)));
	short result_buf[80];

	int frame_num = 0;
	int i = 0;
	int len;
	int before, time;

	memset(&inst_pcm_buf, 80 * 2, 0);
	memset(&inst_index_buf, 82 * 2, 0);

	/* Init decoder */

	inst_g729_dec_h = &inst_g729_dec;
	(*g729ab_dec_reset) (inst_g729_dec_h);
	G729AB_DEC_CONFIG(inst_g729_dec_h, G729_DEC_INPUTFORMAT, 1);

	memset(inst_index_buf, 0, 82 * 2);
	len = fread_a_frame(fbit, inst_index_buf);
	if (len == -2)
		return -1;

	time = 0;
	while (len != -1) {
		//fprintf(stderr, "thread: %d - frame: %d\n", thread_id, frame_num);
		before = cycles();
		G729AB_DEC(inst_g729_dec_h, inst_index_buf, inst_pcm_buf);
		time += cycles() - before;

		/* simulate "hurry up and wait" of real time systems when
		   testing in multi-threaded mode */

		if (multi)
			usleep(10000);

		/* Verify */

		fread(&result_buf, 2, 80, fout);
		for (i = 0; i < 80; i++) {

			if (result_buf[i] != inst_pcm_buf[i]) {

				fprintf(stderr, "diff :%d %hx, %hx\n",
					frame_num * 82 + i, inst_pcm_buf[i],
					result_buf[i]);
				return -1;
			}
		}
		frame_num++;

		memset(inst_index_buf, 0, 82 * 2);
		len = fread_a_frame(fbit, inst_index_buf);
		if (len == -2)
			return -1;
	}

	*av_mips = (float)(time / frame_num) * (FRAMES_PER_SEC / 1E6);

	return 0;
}

int arg_present(int argc, char *argv[], char *t)
{
	int i;

	for (i = 0; i < argc; i++)
		if (strcmp(argv[i], t) == 0)
			return 1;

	return 0;
}

#ifdef SIMGOT
void simgot_init(void);
#endif

void *run_test(void *d)
{
	ARGS *args;
	int argc;
	char **argv;
	int operation;
	int mode;
	FILE *fdata;
	FILE *fcompare;
	int ret;
	float av_mips;
	int multi;

#ifdef SIMGOT
	simgot_init();
#endif

	args = ((struct my_args *)d)->args;
	argc = args->argc;
	argv = args->argv;

	int thread_id = ((struct my_args *)d)->thread_id;

	if (argc < 5) {
		printf("usage: g729ab_test <data file> <compare file> "
		       "<--enc | --dec> <--g729a | --g729ab> [--mips] [--multi]\n");
		exit(-1);
	}

	/* check command line arguments are OK */

	operation = -1;
	if (arg_present(argc, argv, "--enc"))
		operation = 0;
	if (arg_present(argc, argv, "--dec"))
		operation = 1;
	if (operation < 0) {
		fprintf(stderr, "Error: must specify either --enc or --dec\n");
		exit(-1);
	}

	mode = -1;
	if (arg_present(argc, argv, "--g729a"))
		mode = 0;
	if (arg_present(argc, argv, "--g729ab"))
		mode = 1;
	if (mode < 0) {
		fprintf(stderr, "Error: must specify either --g729a or --g729ab\n");
		exit(-1);
	}

	/* attempt to open files */

	fdata = fopen(argv[1], "rb");
	if (fdata == NULL) {
		fprintf(stderr, "Error: can't open data file %s\n", argv[1]);
		exit(-1);
	}

	fcompare = fopen(argv[2], "rb");
	if (fcompare == NULL) {
		fprintf(stderr, "Error: can't open compare file %s\n", argv[2]);
		exit(-1);
	}

	if (arg_present(argc, argv, "--multi"))
		multi = 1;
	else
		multi = 0;

	/* run the actual test */

	if (operation)
		ret = test_decoder(mode, fdata, fcompare, &av_mips, multi, thread_id);
	else
		ret = test_encoder(mode, fdata, fcompare, &av_mips, multi, thread_id);

	fclose(fdata);
	fclose(fcompare);

	/* return 0 for success, -1 for error */

	if (ret) {
		fprintf(stderr, "%s %s %s %s\n", argv[1], argv[2], argv[3], argv[4]);
		exit(-1);
	}

	if (arg_present(argc, argv, "--mips")) {
		printf("Average MIPs: %5.2f", av_mips);
		if (arg_present(argc, argv, "--g729a"))
			printf(" G729A ");
		else
			printf(" G729AB");
		if (arg_present(argc, argv, "--enc"))
			printf(" Encoder\n");
		else
			printf(" Decoder\n");
	}

	pthread_mutex_lock(&active_threads_mutex);
	active_threads--;
	pthread_mutex_unlock(&active_threads_mutex);

	return NULL;
}

struct my_args my_args_enc[NUM_ENC], my_args_dec[NUM_DEC];

int main(int argc, char *argv[])
{
	ARGS args;
	struct my_args my_arg;
	int i;

	/* Set up function ptrs to library functions.  This code is
	   reqd to support the .so version */

#ifdef DLOPEN
	void *handle;
	char *error;

	handle = dlopen("libg729ab.so", RTLD_LAZY);
	if (!handle) {
		fprintf(stderr, "Error opening libg729ab.so : %s\n", dlerror());
		exit(1);
	}
	dlerror();
	g729ab_enc_reset = dlsym(handle, "G729AB_ENC_RESET");
	error = (char *)dlerror();
	if (error != NULL) {
		fprintf(stderr, "%s\n", error);
		exit(1);
	}
	g729ab_enc_process = dlsym(handle, "G729AB_ENC_PROCESS");
	error = (char *)dlerror();
	if (error != NULL) {
		fprintf(stderr, "%s\n", error);
		exit(1);
	}
	g729ab_dec_reset = dlsym(handle, "G729AB_DEC_RESET");
	error = (char *)dlerror();
	if (error != NULL) {
		fprintf(stderr, "%s\n", error);
		exit(1);
	}
	g729ab_dec_process = dlsym(handle, "G729AB_DEC_PROCESS");
	error = (char *)dlerror();
	if (error != NULL) {
		fprintf(stderr, "%s\n", error);
		exit(1);
	}
#else
	g729ab_enc_reset = G729AB_ENC_RESET;
	g729ab_enc_process = G729AB_ENC_PROCESS;
	g729ab_dec_reset = G729AB_DEC_RESET;
	g729ab_dec_process = G729AB_DEC_PROCESS;
#endif

	args.argc = argc;
	args.argv = argv;

	if (arg_present(argc, argv, "--multi")) {
		printf("Multi-threaded test, %d encoders and %d decoders\n",
		       NUM_ENC, NUM_DEC);
		active_threads = 0;

		for (i = 0; i < NUM_ENC; i++) {
			active_threads++;
			my_args_enc[i].args = &args;
			my_args_enc[i].thread_id = i;
			pthread_create(&thread[i], NULL, run_test, (void *)&my_args_enc[i]);
		}

		for (i = 0; i < NUM_DEC; i++) {
			active_threads++;
			my_args_dec[i].args = &args;
			my_args_dec[i].thread_id = i;
			pthread_create(&thread[i + NUM_ENC], NULL, run_test, (void *)&my_args_dec[i]);
		}
	} else {

		/* standard single threaded test */

		active_threads = 1;
		my_arg.args = &args;
		my_arg.thread_id = 0;
		pthread_create(&thread[0], NULL, run_test, (void *)&my_arg);
	}

	while (active_threads)
		usleep(20000);

	return 0;
}
