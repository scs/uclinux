#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "edn.h"
#include "data.h"

#ifdef INLINE
#define inlined 1
#include "edn.c"
#else
#define inlined 0
#endif

/* seconds that each loop should run */
#define LOOPS 10

#define BUF_SIZ 1024

/*********************************************************************
 * Removes a trailing newline character if present
 *********************************************************************/
static void removeNewLine(char * s) {
	if(strlen(s)>0 && s[strlen(s)-1] == '\n') {
		s[strlen(s)-1] = '\0';
	}
}


/***********************************************************************
 * Reads and parses /proc/cpuinfo on a Linux system
 * The pointers must point to pre-allocated arrays of at least BUF_SIZ
 ***********************************************************************/
static float readProcCpuInfo (char *model, char *cache)
{
	FILE * info;
	char * cp;
	int cpus = 0;
	char * buffer_end;
	char *buffer;
	char *vendor_id;
	char *model_name;
	char *cpu_MHz;
	int i;
	float f=0.0;

	buffer = malloc(BUF_SIZ);
	vendor_id = malloc(BUF_SIZ);
	model_name = malloc(BUF_SIZ);
	cpu_MHz = malloc(BUF_SIZ);

	vendor_id[0] = model_name[0] = cpu_MHz[0] = model[0] = cache[0] = '\0';
	info = fopen("/proc/cpuinfo", "r");
	if(info != NULL) {
		/* command did not fail */
		while(NULL != fgets(buffer, BUF_SIZ, info)){
			buffer_end = buffer + strlen(buffer);
			cp = buffer;

			if(! strncmp(buffer, "processor", 9)) {
				cpus++;
			} else if(! strncmp(buffer, "vendor_id", 9)) {
				cp+=strlen("vendor_id");
				while(cp < buffer_end && ( *cp == ' ' || *cp == ':'|| *cp == '\t'))
					cp++;

				if(cp<buffer_end)
					strcpy(vendor_id, cp);

				removeNewLine(vendor_id);

			} else if(! strncmp(buffer, "model name", 10)) {
				cp+=strlen("model name");
				while(cp < buffer_end && ( *cp == ' ' || *cp == ':'|| *cp == '\t'))
					cp++;

				if(cp<buffer_end)
					strcpy(model_name, cp);

				removeNewLine(model_name);

			} else if(! strncmp(buffer, "cpu MHz", 7)) {
				cp+=strlen("cpu MHz");
				while(cp < buffer_end && ( *cp == ' ' || *cp == ':'|| *cp == '\t'))
					cp++;

				if(cp<buffer_end)
					strcpy(cpu_MHz, cp);

				removeNewLine(cpu_MHz);
			} else if(! strncmp(buffer, "cache size", 10)) {
				cp+=strlen("cache size");
				while(cp < buffer_end && ( *cp == ' ' || *cp == ':'|| *cp == '\t'))
					cp++;
				if(cp<buffer_end)
					strcpy(cache, cp);

				removeNewLine(cache);
			}
		}
		if(cpus>1) {
			if (cpus==2) {
				strcpy(model, "Dual");
			} else {
				sprintf(model, "%d CPU", cpus);
			}
		}

		cp = model + strlen(model);
		if(vendor_id[0] != '\0'){
			if(cp != model){
				*cp++ = ' ';
			}
			strcpy(cp, vendor_id);
			cp += strlen(vendor_id);
		}

		if(model_name[0] != '\0'){
			if(cp != model){
				*cp++ = ' ';
			}
			strcpy(cp, model_name);
			cp += strlen(model_name);
		}
		if(cpu_MHz[0] != '\0'){
			if(cp != model){
				*cp++ = ' ';
			}
			f = atof(cpu_MHz);
			i = (int)(f+0.5f);
			sprintf(cpu_MHz, "%dMHz", i);
			strcpy(cp, cpu_MHz);
			cp += strlen(cpu_MHz);
		}
		fclose(info);
	}

	free(buffer);
	free(vendor_id);
	free(model_name);
	free(cpu_MHz);

	return f;
}


double timeval_subtract (struct timeval x, struct timeval y)
{
	struct timeval result;
	double expired;

	(result).tv_sec = (x).tv_sec - (y).tv_sec;
	(result).tv_usec = (x).tv_usec - (y).tv_usec;
	if ((result).tv_usec < 0) {
		--(result).tv_sec;
		(result).tv_usec += 1000000;
	}

	expired = fabs((float)result.tv_sec + ((float)result.tv_usec)/1000000.0);

	return expired;
}

double timespec_subtract (struct timespec x, struct timespec y)
{
	struct timespec result;
	double expired;

	(result).tv_sec = (x).tv_sec - (y).tv_sec;
	(result).tv_nsec = (x).tv_nsec - (y).tv_nsec;
	if ((result).tv_nsec < 0) {
		--(result).tv_sec;
		(result).tv_nsec += 1000000000;
	}

	expired = fabs((float)result.tv_sec + ((float)result.tv_nsec)/1000000000.0);

	return expired;
}

#define time_func(funct, verify) 				\
{							\
	__label__ start_funct, end_funct, cal_start_funct, cal_end_funct, skip_cal, skip_func;	\
	struct rusage start, stop;			\
	struct timespec real_start, real_stop;		\
	unsigned long long count=0, i;			\
	double expired_time = 0.0, expired_real = 0.0, time;	\
	char buf1[256], *buf2, *buf3;						\
										\
	sprintf(buf1, #funct);							\
	if ((buf2 = strchr(buf1, '=')))						\
		buf2 += 2; 							\
	else 									\
		buf2 = buf1;							\
										\
	if ((buf3 = strchr(buf1, '(')))						\
		*buf3 = '\000';							\
										\
	sprintf(buf1, "%s                                           ", buf2);	\
	buf1[15]='\000';							\
	printf("%s", buf1);							\
										\
	if(inlined && max_count && (&&start_funct == &&end_funct)) {		\
		printf("skipping, since it optimized out\n");			\
		goto skip_func;							\
	}									\
	if (inlined && max_count && (&&cal_start_funct == && cal_end_funct)) {	\
		count = max_count/10;						\
		goto skip_cal;							\
	}									\
										\
	time = 0.9;								\
	while(expired_real < 1.0 || expired_real < expired_time) {			\
		count=0;								\
		time += 0.1;								\
		clock_gettime(CLOCK_REALTIME, &real_start);				\
		getrusage(RUSAGE_SELF, &start);						\
		while (1) {								\
			count++;							\
			for (i = 0; i <= 10000 ; i++) {					\
cal_start_funct:;									\
asm __volatile__ ("1: /* start " #funct " */\n");					\
				{ funct; }						\
asm __volatile__ ("2: /* end " #funct " */\n");						\
cal_end_funct:;										\
			}								\
			getrusage(RUSAGE_SELF, &stop);					\
			expired_time = timeval_subtract(stop.ru_utime, start.ru_utime);	\
			if (expired_time >= time)					\
				break;							\
		}									\
		if (verbose) {								\
			verify;								\
		}									\
		clock_gettime(CLOCK_REALTIME, &real_stop);				\
		expired_real = timespec_subtract(real_start, real_stop);		\
	}										\
											\
skip_cal:;										\
	if (!max_count)									\
		max_count = count;							\
	if (max_count < count)								\
		count = max_count;							\
											\
	count = count * LOOPS * 10000;							\
	while(expired_real < (double)LOOPS) {						\
		clock_gettime(CLOCK_REALTIME, &real_start);                             \
		getrusage(RUSAGE_SELF, &start);						\
		for (i = 0; i <= count; i++) {						\
start_funct:;										\
asm __volatile__ ("3: /* start " #funct " */\n");    					\
			funct; 								\
asm __volatile__ ("4: /* end " #funct " */\n");    					\
end_funct:;										\
		}									\
		getrusage(RUSAGE_SELF, &stop);						\
		clock_gettime(CLOCK_REALTIME, &real_stop);                              \
		if (verbose) {								\
			verify;								\
		}									\
		expired_time = timeval_subtract(stop.ru_utime, start.ru_utime);		\
		expired_real = timespec_subtract(real_start, real_stop);		\
		if (expired_real < (double)LOOPS || expired_time < (double)LOOPS || expired_time >= expired_real) \
			count = count * 3 / 2;					\
	}									\
										\
	if ((expired_time*1000000) / count * MHz < 10.0)			\
		printf(" ");							\
	if ((expired_time*1000000) / count * MHz < 100.0)			\
		printf(" ");							\
	if ((expired_time*1000000) / count * MHz < 1000.0)			\
		printf(" ");							\
	if ((expired_time*1000000) / count * MHz < 10000.0)			\
		printf(" ");							\
	printf("%.1f\n", (expired_time*1000000) / count * MHz); 		\
										\
skip_func:;									\
}

void dump(const short *expected, int n)
{
	int i;
	for (i=0; i<n; i++) {
		if ( i % 8 == 0)
			printf("\noutput[%02i] = ", i);
		printf(" %04hx", expected[i]);
	}
	printf("\n");
}

int check_vector(const short *expected, short *actual, int n)
{
	int i, result = 0;

	for (i=0; i<n; i++) {
		if (expected[i] != actual[i]) {
			printf("expected[%d] = %u, actual[%d] = %u\n",
				i, expected[i], i, actual[i]);
			result = 1;
		}
	}

	return result;
}

int check_int_vector(const int *expected, int *actual, int n)
{
	int i, result = 0;

	for (i=0; i<n; i++) {
		if (expected[i] != actual[i]) {
			printf("expected(int)[%d] = %d, actual[%d] = %d\n",
				i, expected[i], i, actual[i]);
			result = 1;
		}
	}
	return result;
}

float calibrate(void)
{
	/* lets figure out the size of a tick */
	struct rusage start, stop;

	getrusage(RUSAGE_SELF, &start);
	getrusage(RUSAGE_SELF, &stop);

	while ((start.ru_utime.tv_sec == stop.ru_utime.tv_sec) && (start.ru_utime.tv_usec == stop.ru_utime.tv_usec))
		getrusage(RUSAGE_SELF, &stop);

	return timeval_subtract(stop.ru_utime, start.ru_utime);
}

#ifdef INLINE
static __inline__ void overhead(void) __attribute__((always_inline));
#endif
void overhead(void)
{
	__asm__ __volatile__ ("nop;\n" : : : "memory");
}

int main(int argc, char *argv[])
{
	short c = 0x3;
	short output[200];
	int int_output[2], g=0xFFFFAAAA;
	long int d = 0xAAAA;
	int e[1] = {0xEEEE};
	char *model;
	char *cache;
	float tick, MHz;
	unsigned long long max_count;
	int verbose=0;

	if (argc > 1)
		verbose = 1;

	printf("\n**\n");
#include "./sysinfo.c"

	model = malloc(BUF_SIZ);
	cache = malloc(BUF_SIZ);

	MHz = readProcCpuInfo (model, cache);
	tick=calibrate();

	printf("**\n");
	printf("** Testing on %s\n** Cache size %s\n", model, cache);
	printf("** CPU MHz = %.0f  kernel tick = %1.1fms or %.0f CPU clocks\n", MHz, tick * 1000, MHz * 1000000.0 * tick);
	printf("** running a test for %i seconds, (%.0f CPU clocks) tick size accounts for less than %.3f%% varation\n",
		 LOOPS, MHz * 1000000.0 * LOOPS,  100 * tick / LOOPS);
	printf("**\n");

	/* Lets check for correctness before we test anything else */
	int_output[0] = int_output[1] = 0;

	memcpy(output, a, sizeof(a));
	vec_mpy1(output, b, c);
	if (check_vector(vec_mpy1_out, output, 150))
		printf("Found a problem in vec_mpy1\n");

	int_output[0] = mac(a, b, c, &int_output[1]);
	if (check_int_vector(mac_out, int_output, 2))
		printf("Found a problem in mac\n");

	fir(a, b, output);
	if (check_vector(fir_out, output, 50))
		printf("Found a problem in fir\n");

	fir_no_red_ld(a, b, output);
	if (check_vector(fir_no_red_ld_out, output, 100))
		printf("Found a problem in fir_no_red_ld\n");

	memcpy(output, a, sizeof(a));
	int_output[0] = latsynth(output, b, N, d);
	if (check_vector(latsynth_out, output, 100) || 
		check_int_vector(latsynth_int_out, int_output, 1))
		printf("Found a problem in latsynth\n");

	bzero(output, sizeof(output));
	iir1(a, b, &output[100], output);
	if (check_vector(iir1_out, output, 101))
		printf("Found a problem in iir1\n");

	output[0] = codebook(d, 1, 17, e[0], g, a, 1||c, 1);
	if (check_vector(codebook_out, output, 1))
		printf("Found a problem in codebook\n");

	memcpy(output, a, sizeof(a));
	jpegdct(output,b);
	if (check_vector(jpegdct_out, output, 64))
		printf("Found a problem in jpegdct\n");

	/*
         * Lets count things now.
         */

	printf("Test\tcycles per loop\n");

	max_count = 0;

	time_func(overhead(), dump(output,0));

	time_func(vec_mpy1(output, b, c), dump(output, 150));

	time_func(int_output[0] = mac(a, b, c, &int_output[1]), dump((short *)int_output,4));

	time_func(fir(a, b, output), dump(output, 50));

	time_func(fir_no_red_ld(a, b, output), dump(output, 100));

	time_func(d = latsynth(a, b, N, d), dump(output, 100));

	time_func(iir1(a, b, &output[100], output), dump(output, 101));

	time_func(output[0] = codebook(d, 1, 17, e[0], g, a, 1||c, 1), dump(output,2));

	memcpy(output, a, sizeof(a));
	time_func(jpegdct(output, b), dump(output, 64));

	free(model);
	free(cache);

	return 0;
}

