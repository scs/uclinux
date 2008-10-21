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
#include "interfaces.h"

int cpufreq_cpu_exists(unsigned int cpu)
{
	int ret = sysfs_cpu_exists(cpu);
	if (ret == -ENOSYS)
		ret = proc_cpu_exists(cpu);
	return (ret);
}

unsigned long cpufreq_get_freq_kernel(unsigned int cpu)
{
	unsigned long ret = sysfs_get_freq_kernel(cpu);
	if (!ret)
		ret = proc_get_freq_kernel(cpu);
	return (ret);
}

unsigned long cpufreq_get_freq_hardware(unsigned int cpu)
{
	unsigned long ret = sysfs_get_freq_hardware(cpu);
	if (!ret)
		ret = proc_get_freq_hardware(cpu);
	return (ret);
}

int cpufreq_get_hardware_limits(unsigned int cpu,
				unsigned long *min,
				unsigned long *max)
{
	int ret;
	if ((!min) || (!max))
		return -EINVAL;
	ret = sysfs_get_hardware_limits(cpu, min, max);
	if (ret)
		ret = proc_get_hardware_limits(cpu, min, max);
	return (ret);
}

char * cpufreq_get_driver(unsigned int cpu) {
	char * ret;
	ret = sysfs_get_driver(cpu);
	if (!ret) {
		ret = proc_get_driver(cpu);
	}
	return (ret);
}

void cpufreq_put_driver(char * ptr) {
	if (!ptr)
		return;
	free(ptr);
}

struct cpufreq_policy * cpufreq_get_policy(unsigned int cpu) {
	struct cpufreq_policy * ret;
	ret = sysfs_get_policy(cpu);
	if (!ret)
		ret = proc_get_policy(cpu);
	return (ret);
}

void cpufreq_put_policy(struct cpufreq_policy *policy) {
	if ((!policy) || (!policy->governor))
		return;

	free(policy->governor);
	policy->governor = NULL;
	free(policy);
}

struct cpufreq_available_governors * cpufreq_get_available_governors(unsigned int cpu) {
	struct cpufreq_available_governors *ret;
	ret = sysfs_get_available_governors(cpu);
	if (!ret)
		ret = proc_get_available_governors(cpu);
	return (ret);
}

void cpufreq_put_available_governors(struct cpufreq_available_governors *any) {
	struct cpufreq_available_governors *tmp, *next;

	if (!any)
		return;

	tmp = any->first;
	while (tmp) {
		next = tmp->next;
		if (tmp->governor)
			free(tmp->governor);
		free(tmp);
		tmp = next;
	}
}


struct cpufreq_available_frequencies * cpufreq_get_available_frequencies(unsigned int cpu) {
	struct cpufreq_available_frequencies * ret;
	ret = sysfs_get_available_frequencies(cpu);
	if (!ret)
		ret = proc_get_available_frequencies(cpu);
	return (ret);
}

void cpufreq_put_available_frequencies(struct cpufreq_available_frequencies *any) {
	struct cpufreq_available_frequencies *tmp, *next;

	if (!any)
		return;

	tmp = any->first;
	while (tmp) {
		next = tmp->next;
		free(tmp);
		tmp = next;
	}
}


struct cpufreq_affected_cpus * cpufreq_get_affected_cpus(unsigned int cpu) {
	struct cpufreq_affected_cpus * ret;
	ret = sysfs_get_affected_cpus(cpu);
	if (!ret)
		ret = proc_get_affected_cpus(cpu);
	return (ret);
}

void cpufreq_put_affected_cpus(struct cpufreq_affected_cpus *any) {
	struct cpufreq_affected_cpus *tmp, *next;

	if (!any)
		return;

	tmp = any->first;
	while (tmp) {
		next = tmp->next;
		free(tmp);
		tmp = next;
	}
}


int cpufreq_set_policy(unsigned int cpu, struct cpufreq_policy *policy) {
	int ret;
	if (!policy || !(policy->governor))
		return -EINVAL;

	ret = sysfs_set_policy(cpu, policy);
	if (ret)
		ret = proc_set_policy(cpu, policy);
	return (ret);
}


int cpufreq_modify_policy_min(unsigned int cpu, unsigned long min_freq) {
	int ret;

	ret = sysfs_modify_policy_min(cpu, min_freq);
	if (ret)
		ret = proc_modify_policy_min(cpu, min_freq);
	return (ret);
}


int cpufreq_modify_policy_max(unsigned int cpu, unsigned long max_freq) {
	int ret;

	ret = sysfs_modify_policy_max(cpu, max_freq);
	if (ret)
		ret = proc_modify_policy_max(cpu, max_freq);
	return (ret);
}


int cpufreq_modify_policy_governor(unsigned int cpu, char *governor) {
	int ret;

	if ((!governor) || (strlen(governor) > 19))
		return -EINVAL;

	ret = sysfs_modify_policy_governor(cpu, governor);
	if (ret)
		ret = proc_modify_policy_governor(cpu, governor);
	return (ret);
}

int cpufreq_set_frequency(unsigned int cpu, unsigned long target_frequency) {
	int ret;

	ret = sysfs_set_frequency(cpu, target_frequency);
	if (ret)
		ret = proc_set_frequency(cpu, target_frequency);
	return (ret);
}

struct cpufreq_stats * cpufreq_get_stats(unsigned int cpu, unsigned long long *total_time) {
	struct cpufreq_stats *ret;

	ret = sysfs_get_stats(cpu, total_time);
	return (ret);
}

void cpufreq_put_stats(struct cpufreq_stats *any) {
	struct cpufreq_stats *tmp, *next;

	if (!any)
		return;

	tmp = any->first;
	while (tmp) {
		next = tmp->next;
		free(tmp);
		tmp = next;
	}
}

unsigned long cpufreq_get_transitions(unsigned int cpu) {
	unsigned long ret = sysfs_get_transitions(cpu);

	return (ret);
}
