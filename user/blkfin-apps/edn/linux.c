#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "edn.h"
#include "data.h"

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

#define time_func(funct) 				\
{							\
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
	time = 0.5;								\
	while(expired_real < 1.0) {						\
		time += 0.5;								\
		clock_gettime(CLOCK_REALTIME, &real_start);				\
		getrusage(RUSAGE_SELF, &start);						\
		while (1) {								\
			count++;							\
			for (i = 0; i <= 10000 ; i++)					\
				funct;							\
			getrusage(RUSAGE_SELF, &stop);					\
			if (timeval_subtract(stop.ru_utime, start.ru_utime) >= time)	\
				break;							\
		}									\
		clock_gettime(CLOCK_REALTIME, &real_stop);				\
		expired_real = timespec_subtract(real_start, real_stop);		\
	}										\
										\
	count = count * LOOPS * 10000;						\
	while(expired_real < (double)LOOPS) {					\
		clock_gettime(CLOCK_REALTIME, &real_start);                             \
		getrusage(RUSAGE_SELF, &start);						\
		for (i = 0; i < count; i++) {						\
			funct;								\
		}									\
		getrusage(RUSAGE_SELF, &stop);						\
		clock_gettime(CLOCK_REALTIME, &real_stop);                              \
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

void overhead(void)
{
	__asm__ __volatile__ ("nop;\n");
}

int main(void)
{
	short c = 0x3;
	short output[200];
	int int_output[2];
	long int d = 0xAAAA;
	int e[1] = {0xEEEE};
	char *model;
	char *cache;
	float tick, MHz;

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

	/*
         * Declared as memory variable so it doesn't get optimized out
         */

	printf("Test\tcycles per loop\n");

	time_func(overhead());

	time_func(vec_mpy1(a, b, c));

	time_func(int_output[0] = mac(a, b, c, &int_output[1]));

	time_func(fir(a, b, output));

	time_func(fir_no_red_ld(a, b, output));

	time_func(d = latsynth(a, b, N, d));

	time_func(iir1(a, b, &output[100], output));

	time_func(e[0] = codebook(d, 1, 17, e[0], d, a, c, 1));

	time_func(jpegdct(a, b));

	free(model);
	free(cache);

	return 0;
}

