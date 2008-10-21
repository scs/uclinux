/*
 *  (C) 2004  Dominik Brodowski <linux@dominikbrodowski.de>
 *
 *  Licensed under the terms of the GNU GPL License version 2.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "cpufreq.h"

#define PATH_TO_CPU "/sys/devices/system/cpu/"
#define MAX_LINE_LEN 255
#define SYSFS_PATH_MAX 255

/* helper function to read file from /sys into given buffer */
/* fname is a relative path under "cpuX/cpufreq" dir */
unsigned int sysfs_read_file(unsigned int cpu, const char *fname, char *buf, size_t buflen)
{
	char path[SYSFS_PATH_MAX];
	int fd;
	size_t numread;

	snprintf(path, sizeof(path), PATH_TO_CPU "cpu%u/cpufreq/%s",
			 cpu, fname);

	if ( ( fd = open(path, O_RDONLY) ) == -1 )
		return 0;

	numread = read(fd, buf, buflen - 1);
	if ( numread < 1 )
	{
		close(fd);
		return 0;
	}

	buf[numread] = '\0';
	close(fd);

	return numread;
}

/* helper function to write a new value to a /sys file */
/* fname is a relative path under "cpuX/cpufreq" dir */
unsigned int sysfs_write_file(unsigned int cpu, const char *fname, const char *value, size_t len)
{
	char path[SYSFS_PATH_MAX];
	int fd;
	size_t numwrite;

	snprintf(path, sizeof(path), PATH_TO_CPU "cpu%u/cpufreq/%s",
			 cpu, fname);

	if ( ( fd = open(path, O_WRONLY) ) == -1 )
		return 0;

	numwrite = write(fd, value, len);
	if ( numwrite < 1 )
	{
		close(fd);
		return 0;
	}

	close(fd);

	return numwrite;
}

/* read access to files which contain one numeric value */

enum {
	CPUINFO_CUR_FREQ,
	CPUINFO_MIN_FREQ,
	CPUINFO_MAX_FREQ,
	SCALING_CUR_FREQ,
	SCALING_MIN_FREQ,
	SCALING_MAX_FREQ,
	STATS_NUM_TRANSITIONS,
	MAX_VALUE_FILES
};

static const char *value_files[MAX_VALUE_FILES] = {
	[CPUINFO_CUR_FREQ] = "cpuinfo_cur_freq",
	[CPUINFO_MIN_FREQ] = "cpuinfo_min_freq",
	[CPUINFO_MAX_FREQ] = "cpuinfo_max_freq",
	[SCALING_CUR_FREQ] = "scaling_cur_freq",
	[SCALING_MIN_FREQ] = "scaling_min_freq",
	[SCALING_MAX_FREQ] = "scaling_max_freq",
	[STATS_NUM_TRANSITIONS] = "stats/total_trans"
};


static unsigned long sysfs_get_one_value(unsigned int cpu, unsigned int which)
{
 	unsigned long value;
	unsigned int len;
	char linebuf[MAX_LINE_LEN];
	char *endp;

	if ( which >= MAX_VALUE_FILES )
		return 0;

	if ( ( len = sysfs_read_file(cpu, value_files[which], linebuf, sizeof(linebuf))) == 0 )
	{
		return 0;
	}

	value = strtoul(linebuf, &endp, 0);

	if ( endp == linebuf || errno == ERANGE )
		return 0;

	return value;
}

/* read access to files which contain one string */

enum {
	SCALING_DRIVER,
	SCALING_GOVERNOR,
	MAX_STRING_FILES
};

static const char *string_files[MAX_STRING_FILES] = {
	[SCALING_DRIVER] = "scaling_driver",
	[SCALING_GOVERNOR] = "scaling_governor",
};


static char * sysfs_get_one_string(unsigned int cpu, unsigned int which)
{
	char linebuf[MAX_LINE_LEN];
	char *result;
	unsigned int len;

	if (which >= MAX_STRING_FILES)
		return NULL;

	if ( ( len = sysfs_read_file(cpu, string_files[which], linebuf, sizeof(linebuf))) == 0 )
	{
		return NULL;
	}

	if ( ( result = strdup(linebuf) ) == NULL )
		return NULL;

	if (result[strlen(result) - 1] == '\n')
		result[strlen(result) - 1] = '\0';

	return result;
}

/* write access */

enum {
	WRITE_SCALING_MIN_FREQ,
	WRITE_SCALING_MAX_FREQ,
	WRITE_SCALING_GOVERNOR,
	WRITE_SCALING_SET_SPEED,
	MAX_WRITE_FILES
};

static const char *write_files[MAX_VALUE_FILES] = {
	[WRITE_SCALING_MIN_FREQ] = "scaling_min_freq",
	[WRITE_SCALING_MAX_FREQ] = "scaling_max_freq",
	[WRITE_SCALING_GOVERNOR] = "scaling_governor",
	[WRITE_SCALING_SET_SPEED] = "scaling_setspeed",
};

static int sysfs_write_one_value(unsigned int cpu, unsigned int which,
				 const char *new_value, size_t len)
{
	if (which >= MAX_WRITE_FILES)
		return 0;

	if ( sysfs_write_file(cpu, write_files[which], new_value, len) != len )
		return -ENODEV;

	return 0;
};


int sysfs_cpu_exists(unsigned int cpu)
{
	char file[SYSFS_PATH_MAX];
	struct stat statbuf;

	snprintf(file, SYSFS_PATH_MAX, PATH_TO_CPU "cpu%u/", cpu);

	if ( stat(file, &statbuf) != 0 )
		return -ENOSYS;

	return S_ISDIR(statbuf.st_mode) ? 0 : -ENOSYS;
}


unsigned long sysfs_get_freq_kernel(unsigned int cpu)
{
	return sysfs_get_one_value(cpu, SCALING_CUR_FREQ);
}

unsigned long sysfs_get_freq_hardware(unsigned int cpu)
{
	return sysfs_get_one_value(cpu, CPUINFO_CUR_FREQ);
}

int sysfs_get_hardware_limits(unsigned int cpu,
			      unsigned long *min,
			      unsigned long *max)
{
	if ((!min) || (!max))
		return -EINVAL;

	*min = sysfs_get_one_value(cpu, CPUINFO_MIN_FREQ);
	if (!*min)
		return -ENODEV;

	*max = sysfs_get_one_value(cpu, CPUINFO_MAX_FREQ);
	if (!*max)
		return -ENODEV;

	return 0;
}

char * sysfs_get_driver(unsigned int cpu) {
	return sysfs_get_one_string(cpu, SCALING_DRIVER);
}

struct cpufreq_policy * sysfs_get_policy(unsigned int cpu) {
	struct cpufreq_policy *policy;

	policy = malloc(sizeof(struct cpufreq_policy));
	if (!policy)
		return NULL;

	policy->governor = sysfs_get_one_string(cpu, SCALING_GOVERNOR);
	if (!policy->governor) {
		free(policy);
		return NULL;
	}
	policy->min = sysfs_get_one_value(cpu, SCALING_MIN_FREQ);
	policy->max = sysfs_get_one_value(cpu, SCALING_MAX_FREQ);
	if ((!policy->min) || (!policy->max)) {
		free(policy->governor);
		free(policy);
		return NULL;
	}

	return policy;
}

struct cpufreq_available_governors * sysfs_get_available_governors(unsigned int cpu) {
	struct cpufreq_available_governors *first = NULL;
	struct cpufreq_available_governors *current = NULL;
	char linebuf[MAX_LINE_LEN];
	unsigned int pos, i;
	unsigned int len;

	if ( ( len = sysfs_read_file(cpu, "scaling_available_governors", linebuf, sizeof(linebuf))) == 0 )
	{
		return NULL;
	}

	pos = 0;
	for ( i = 0; i < len; i++ )
	{
		if ( linebuf[i] == ' ' || linebuf[i] == '\n' )
		{
			if ( i - pos < 2 )
				continue;
			if ( current ) {
				current->next = malloc(sizeof *current );
				if ( ! current->next )
					goto error_out;
				current = current->next;
			} else {
				first = malloc( sizeof *first );
				if ( ! first )
					goto error_out;
				current = first;
			}
			current->first = first;
			current->next = NULL;

			current->governor = malloc(i - pos + 1);
			if ( ! current->governor )
				goto error_out;

			memcpy( current->governor, linebuf + pos, i - pos);
			current->governor[i - pos] = '\0';
			pos = i + 1;
		}
	}

	return first;

 error_out:
	while ( first ) {
		current = first->next;
		if ( first->governor )
			free( first->governor );
		free( first );
		first = current;
	}
	return NULL;
}


struct cpufreq_available_frequencies * sysfs_get_available_frequencies(unsigned int cpu) {
	struct cpufreq_available_frequencies *first = NULL;
	struct cpufreq_available_frequencies *current = NULL;
	char one_value[SYSFS_PATH_MAX];
	char linebuf[MAX_LINE_LEN];
	unsigned int pos, i;
	unsigned int len;

	if ( ( len = sysfs_read_file(cpu, "scaling_available_frequencies", linebuf, sizeof(linebuf))) == 0 )
	{
		return NULL;
	}

	pos = 0;
	for ( i = 0; i < len; i++ )
	{
		if ( linebuf[i] == ' ' || linebuf[i] == '\n' )
		{
			if ( i - pos < 2 )
				continue;
			if ( i - pos >= SYSFS_PATH_MAX )
				goto error_out;
			if ( current ) {
				current->next = malloc(sizeof *current );
				if ( ! current->next )
					goto error_out;
				current = current->next;
			} else {
				first = malloc(sizeof *first );
				if ( ! first )
					goto error_out;
				current = first;
			}
			current->first = first;
			current->next = NULL;

			memcpy(one_value, linebuf + pos, i - pos);
			one_value[i - pos] = '\0';
			if ( sscanf(one_value, "%lu", &current->frequency) != 1 )
				goto error_out;

			pos = i + 1;
		}
	}

	return first;

 error_out:
	while ( first ) {
		current = first->next;
		free(first);
		first = current;
	}
	return NULL;
}

struct cpufreq_affected_cpus * sysfs_get_affected_cpus(unsigned int cpu) {
	struct cpufreq_affected_cpus *first = NULL;
	struct cpufreq_affected_cpus *current = NULL;
	char one_value[SYSFS_PATH_MAX];
	char linebuf[MAX_LINE_LEN];
	unsigned int pos, i;
	unsigned int len;

	if ( ( len = sysfs_read_file(cpu, "affected_cpus", linebuf, sizeof(linebuf))) == 0 )
	{
		return NULL;
	}

	pos = 0;
	for ( i = 0; i < len; i++ )
	{
		if ( i == len || linebuf[i] == ' ' || linebuf[i] == '\n' )
		{
			if ( i - pos  < 1 )
				continue;
			if ( i - pos >= SYSFS_PATH_MAX )
				goto error_out;
			if ( current ) {
				current->next = malloc(sizeof *current);
				if ( ! current->next )
					goto error_out;
				current = current->next;
			} else {
				first = malloc(sizeof *first);
				if ( ! first )
					goto error_out;
				current = first;
			}
			current->first = first;
			current->next = NULL;

			memcpy(one_value, linebuf + pos, i - pos);
			one_value[i - pos] = '\0';

			if ( sscanf(one_value, "%u", &current->cpu) != 1 )
				goto error_out;

			pos = i + 1;
		}
	}

	return first;

 error_out:
	while (first) {
		current = first->next;
		free(first);
		first = current;
	}
	return NULL;
}

struct cpufreq_stats * sysfs_get_stats(unsigned int cpu, unsigned long *total_time) {
	struct cpufreq_stats *first = NULL;
	struct cpufreq_stats *current = NULL;
	char one_value[SYSFS_PATH_MAX];
	char linebuf[MAX_LINE_LEN];
	unsigned int pos, i;
	unsigned int len;

	if ( ( len = sysfs_read_file(cpu, "stats/time_in_state", linebuf, sizeof(linebuf))) == 0 )
		return NULL;

	*total_time = 0;
	pos = 0;
	for ( i = 0; i < len; i++ )
	{
		if ( i == strlen(linebuf) || linebuf[i] == '\n' )
		{
			if ( i - pos < 2 )
				continue;
			if ( (i - pos) >= SYSFS_PATH_MAX )
				goto error_out;
			if ( current ) {
				current->next = malloc(sizeof *current );
				if ( ! current->next )
					goto error_out;
				current = current->next;
			} else {
				first = malloc(sizeof *first );
				if ( ! first )
					goto error_out;
				current = first;
			}
			current->first = first;
			current->next = NULL;

			memcpy(one_value, linebuf + pos, i - pos);
			one_value[i - pos] = '\0';
			if ( sscanf(one_value, "%lu %llu", &current->frequency, &current->time_in_state) != 2 )
				goto error_out;

			*total_time = *total_time + current->time_in_state;
			pos = i + 1;
		}
	}

	return first;

 error_out:
	while ( first ) {
		current = first->next;
		free(first);
		first = current;
	}
	return NULL;
}

unsigned long sysfs_get_transitions(unsigned int cpu)
{
	return sysfs_get_one_value(cpu, STATS_NUM_TRANSITIONS);
}

static int verify_gov(char *new_gov, char *passed_gov)
{
	unsigned int i, j=0;

	if (!passed_gov || (strlen(passed_gov) > 19))
		return -EINVAL;

	strncpy(new_gov, passed_gov, 20);
	for (i=0;i<20;i++) {
		if (j) {
			new_gov[i] = '\0';
			continue;
		}
		if ((new_gov[i] >= 'a') && (new_gov[i] <= 'z')) {
			continue;
		}
		if ((new_gov[i] >= 'A') && (new_gov[i] <= 'Z')) {
			continue;
		}
		if (new_gov[i] == '-') {
			continue;
		}
		if (new_gov[i] == '_') {
			continue;
		}
		if (new_gov[i] == '\0') {
			j = 1;
			continue;
		}
		return -EINVAL;
	}
	new_gov[19] = '\0';
	return 0;
}

int sysfs_modify_policy_governor(unsigned int cpu, char *governor)
{
	char new_gov[SYSFS_PATH_MAX];

	if (!governor)
		return -EINVAL;

	if (verify_gov(new_gov, governor))
		return -EINVAL;

	return sysfs_write_one_value(cpu, WRITE_SCALING_GOVERNOR, new_gov, strlen(new_gov));
};

int sysfs_modify_policy_max(unsigned int cpu, unsigned long max_freq)
{
	char value[SYSFS_PATH_MAX];

	snprintf(value, SYSFS_PATH_MAX, "%lu", max_freq);

	return sysfs_write_one_value(cpu, WRITE_SCALING_MAX_FREQ, value, strlen(value));
};


int sysfs_modify_policy_min(unsigned int cpu, unsigned long min_freq)
{
	char value[SYSFS_PATH_MAX];

	snprintf(value, SYSFS_PATH_MAX, "%lu", min_freq);

	return sysfs_write_one_value(cpu, WRITE_SCALING_MIN_FREQ, value, strlen(value));
};


int sysfs_set_policy(unsigned int cpu, struct cpufreq_policy *policy)
{
	char min[SYSFS_PATH_MAX];
	char max[SYSFS_PATH_MAX];
	char gov[SYSFS_PATH_MAX];
	int ret;
	unsigned long old_min;
	int write_max_first;

	if (!policy || !(policy->governor))
		return -EINVAL;

	if (policy->max < policy->min)
		return -EINVAL;

	if (verify_gov(gov, policy->governor))
		return -EINVAL;

	snprintf(min, SYSFS_PATH_MAX, "%lu", policy->min);
	snprintf(max, SYSFS_PATH_MAX, "%lu", policy->max);

	old_min = sysfs_get_one_value(cpu, SCALING_MIN_FREQ);
	write_max_first = (old_min && (policy->max < old_min) ? 0 : 1);

	if (write_max_first) {
		ret = sysfs_write_one_value(cpu, WRITE_SCALING_MAX_FREQ, max, strlen(max));
		if (ret)
			return ret;
	}

	ret = sysfs_write_one_value(cpu, WRITE_SCALING_MIN_FREQ, min, strlen(min));
	if (ret)
		return ret;

	if (!write_max_first) {
		ret = sysfs_write_one_value(cpu, WRITE_SCALING_MAX_FREQ, max, strlen(max));
		if (ret)
			return ret;
	}

	return sysfs_write_one_value(cpu, WRITE_SCALING_GOVERNOR, gov, strlen(gov));
}

int sysfs_set_frequency(unsigned int cpu, unsigned long target_frequency) {
	struct cpufreq_policy *pol = sysfs_get_policy(cpu);
	char userspace_gov[] = "userspace";
	char freq[SYSFS_PATH_MAX];
	int ret;

	if (!pol)
		return -ENODEV;

	if (strncmp(pol->governor, userspace_gov, 9) != 0) {
		ret = sysfs_modify_policy_governor(cpu, userspace_gov);
		if (ret) {
			cpufreq_put_policy(pol);
			return (ret);
		}
	}

	cpufreq_put_policy(pol);

	snprintf(freq, SYSFS_PATH_MAX, "%lu", target_frequency);

	return sysfs_write_one_value(cpu, WRITE_SCALING_SET_SPEED, freq, strlen(freq));
}
