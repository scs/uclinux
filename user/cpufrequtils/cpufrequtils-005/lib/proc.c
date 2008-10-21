/*
 *  (C) 2004  Dominik Brodowski <linux@dominikbrodowski.de>
 *
 *  Licensed under the terms of the GNU GPL License version 2.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "cpufreq.h"

#define MAX_LINE_LEN 255

static int readout_proc_cpufreq(unsigned int cpu, unsigned long *min, unsigned long *max, char **governor)
{
	FILE *fp;
	char value[MAX_LINE_LEN];
	char gov_value[MAX_LINE_LEN];
	int ret = -ENODEV;
	unsigned int cpu_read;
	unsigned int tmp1, tmp2;

	if ((!min) || (!max) || (!governor))
		return -EINVAL;

	fp = fopen("/proc/cpufreq","r");
	if (!fp)
		return -ENODEV;


	fgets(value, MAX_LINE_LEN, fp);
	if (strlen(value) > (MAX_LINE_LEN - 10)) {
		ret = -EIO;
		goto error;
	}

	while(!feof(fp)) {
		fgets(value, MAX_LINE_LEN, fp);
		if (strlen(value) > (MAX_LINE_LEN - 10)) {
			ret = -EIO;
			goto error;
		}

		ret = sscanf(value, "CPU%3d    %9lu kHz (%3d %%)  -  %9lu kHz (%3d %%)  -  %s",
			     &cpu_read , min, &tmp1, max, &tmp2, gov_value);
		if (ret != 6) {
			ret = -EIO;
			goto error;
		}

		if (cpu_read != cpu)
			continue;

		if ((tmp2 < tmp1) || (tmp2 > 100) || (*max < *min)) {
			ret = -ENOSYS;
			goto error;
		}

		tmp1 = strlen(gov_value);
		if (tmp1 > 20) {
			ret = -ENOSYS;
			goto error;
		}

		*governor = malloc(sizeof(char) * (tmp1 + 2));
		if (!*governor) {
			ret = -ENOMEM;
			goto error;
		}

		strncpy(*governor, gov_value, tmp1);
		(*governor)[tmp1] = '\0';

		ret = 0;

		break;
	}

 error:
	fclose(fp);
	return (ret);
}

int proc_cpu_exists(unsigned int cpu) {
	unsigned long tmp1, tmp2;
	char *tmp3;
	int ret;

	ret = readout_proc_cpufreq(cpu, &tmp1, &tmp2, &tmp3);
	if (ret)
		return -ENODEV;

	free(tmp3);
	return 0;
}

struct cpufreq_policy * proc_get_policy(unsigned int cpu) {
	struct cpufreq_policy tmp;
	struct cpufreq_policy *ret;
	int err;

	err = readout_proc_cpufreq(cpu, &tmp.min, &tmp.max, &tmp.governor);
	if (err)
		return NULL;

	ret = malloc(sizeof(struct cpufreq_policy));
	if (!ret)
		return NULL;

	ret->min = tmp.min;
	ret->max = tmp.max;
	ret->governor = tmp.governor;

	return (ret);
}

unsigned long proc_get_freq_kernel(unsigned int cpu) {
	FILE *fp;
	char value[MAX_LINE_LEN];
	char file[MAX_LINE_LEN];
	unsigned long value2;

	snprintf(file, MAX_LINE_LEN, "/proc/sys/cpu/%u/speed", cpu);

	fp = fopen(file,"r");
	if (!fp)
		return 0;
	fgets(value, MAX_LINE_LEN, fp);
	fclose(fp);

	if (strlen(value) > (MAX_LINE_LEN - 10)) {
		return 0;
	}

	if (sscanf(value, "%lu", &value2) != 1)
		return 0;

	return value2;
}

int proc_set_policy(unsigned int cpu, struct cpufreq_policy *policy) {
	FILE *fp;
	char value[MAX_LINE_LEN];
	int ret = -ENODEV;

	if ((!policy) || (!policy->governor) || (strlen(policy->governor) > 15))
		return -EINVAL;

	snprintf(value, MAX_LINE_LEN, "%d:%lu:%lu:%s", cpu, policy->min, policy->max, policy->governor);

	value[MAX_LINE_LEN - 1]='\0';

	fp = fopen("/proc/cpufreq","r+");
	if (!fp)
		return -ENODEV;
	ret = fputs(value, fp);
	fclose(fp);

	if (ret < 0)
		return (ret);

	return 0;
}

int proc_set_frequency(unsigned int cpu, unsigned long target_frequency) {
	struct cpufreq_policy *pol = proc_get_policy(cpu);
	struct cpufreq_policy new_pol;
	char userspace_gov[] = "userspace";
	FILE *fp;
	char value[MAX_LINE_LEN];
	char file[MAX_LINE_LEN];
	int ret = 0;

	if (!pol)
		return -ENODEV;

	if (strncmp(pol->governor, userspace_gov, 9) != 0) {
		cpufreq_put_policy(pol);
		new_pol.min = pol->min;
		new_pol.max = pol->max;
		new_pol.governor = userspace_gov;
		ret = proc_set_policy(cpu, &new_pol);
		if (ret)
			return (ret);
	}


	snprintf(file, MAX_LINE_LEN, "/proc/sys/cpu/%u/speed", cpu);
	snprintf(value, MAX_LINE_LEN, "%lu", target_frequency);

	fp = fopen(file,"r+");
	if (!fp)
		return -EINVAL;
	ret = fputs(value, fp);
	fclose(fp);

	if (ret < 0)
		return (ret);

	return 0;
}
