/*
 *  (C) 2004-2005  Dominik Brodowski <linux@dominikbrodowski.de>
 *
 *  Licensed under the terms of the GNU GPL License version 2.
 */


#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>

#include <getopt.h>

#include "cpufreq.h"


#ifdef NLS
#include <libintl.h>
#define _(String) gettext (String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)
#else
#define gettext_noop(String) String
#define _(String) gettext_noop (String)
#define gettext(String) gettext_noop (String)
#define N_(String) gettext_noop (String)
#define textdomain(String)
#endif

#define LINE_LEN 10

static unsigned int count_cpus(void)
{
	FILE *fp;
	char value[LINE_LEN];
	unsigned int ret = 0;
	unsigned int cpunr = 0;

	fp = fopen("/proc/stat", "r");
	if(!fp) {
		printf(gettext("Couldn't count the number of CPUs (%s: %s), assuming 1\n"), "/proc/stat", strerror(errno));
		return 1;
	}

	while (!feof(fp)) {
		fgets(value, LINE_LEN, fp);
		value[LINE_LEN - 1] = '\0';
		if (strlen(value) < (LINE_LEN - 2))
			continue;
		if (strstr(value, "cpu "))
			continue;
		if (sscanf(value, "cpu%d ", &cpunr) != 1)
			continue;
		if (cpunr > ret)
			ret = cpunr;
	}
	fclose(fp);

	/* cpu count starts from 0, on error return 1 (UP) */
	return (ret+1);
}


static void proc_cpufreq_output(void)
{
	unsigned int cpu, nr_cpus;
	struct cpufreq_policy *policy;
	unsigned int min_pctg = 0;
	unsigned int max_pctg = 0;
	unsigned long min, max;

	printf(gettext("          minimum CPU frequency  -  maximum CPU frequency  -  governor\n"));

	nr_cpus = count_cpus();
	for (cpu=0; cpu < nr_cpus; cpu++) {
		policy = cpufreq_get_policy(cpu);
		if (!policy)
			continue;

		if (cpufreq_get_hardware_limits(cpu, &min, &max)) {
			max = 0;
		} else {
			min_pctg = (policy->min * 100) / max;
			max_pctg = (policy->max * 100) / max;
		}
		printf("CPU%3d    %9lu kHz (%3d %%)  -  %9lu kHz (%3d %%)  -  %s\n",
		       cpu , policy->min, max ? min_pctg : 0, policy->max, max ? max_pctg : 0, policy->governor);

		cpufreq_put_policy(policy);
	}
}

static void print_speed(unsigned long speed)
{
	unsigned long tmp;

	if (speed > 1000000) {
		tmp = speed % 10000;
		if (tmp >= 5000)
			speed += 10000;
		printf ("%u.%02u GHz", ((unsigned int) speed/1000000),
			((unsigned int) (speed%1000000)/10000));
	} else if (speed > 100000) {
		tmp = speed % 1000;
		if (tmp >= 500)
			speed += 1000;
		printf ("%u MHz", ((unsigned int) speed / 1000));
	} else if (speed > 1000) {
		tmp = speed % 100;
		if (tmp >= 50)
			speed += 100;
		printf ("%u.%01u MHz", ((unsigned int) speed/1000),
			((unsigned int) (speed%1000)/100));
	} else
		printf ("%lu kHz", speed);

	return;
}

static void debug_output_one(unsigned int cpu)
{
	char *driver;
	struct cpufreq_affected_cpus *cpus;
	struct cpufreq_available_frequencies *freqs;
	unsigned long min, max, freq_kernel, freq_hardware;
	unsigned long total_trans;
	unsigned long long total_time;
	struct cpufreq_policy *policy;
	struct cpufreq_available_governors * governors;
	struct cpufreq_stats *stats;

	if (cpufreq_cpu_exists(cpu)) {
		printf(gettext ("couldn't analyze CPU %d as it doesn't seem to be present\n"), cpu);
		return;
	}

	printf(gettext ("analyzing CPU %d:\n"), cpu);

	freq_kernel = cpufreq_get_freq_kernel(cpu);
	freq_hardware = cpufreq_get_freq_hardware(cpu);

	driver = cpufreq_get_driver(cpu);
	if (!driver) {
		printf(gettext ("  no or unknown cpufreq driver is active on this CPU\n"));
	} else {
		printf(gettext ("  driver: %s\n"), driver);
		cpufreq_put_driver(driver);
	}

	cpus = cpufreq_get_affected_cpus(cpu);
	if (cpus) {
		printf(gettext ("  CPUs which need to switch frequency at the same time: "));
		while (cpus->next) {
			printf("%d ", cpus->cpu);
			cpus = cpus->next;
		}
		printf("%d\n", cpus->cpu);
		cpufreq_put_affected_cpus(cpus);
	}

	if (!(cpufreq_get_hardware_limits(cpu, &min, &max))) {
		printf(gettext ("  hardware limits: "));
		print_speed(min);
		printf(" - ");
		print_speed(max);
		printf("\n");
	}

	freqs = cpufreq_get_available_frequencies(cpu);
	if (freqs) {
		printf(gettext ("  available frequency steps: "));
		while (freqs->next) {
			print_speed(freqs->frequency);
			printf(", ");
			freqs = freqs->next;
		}
		print_speed(freqs->frequency);
		printf("\n");
		cpufreq_put_available_frequencies(freqs);
	}

	governors = cpufreq_get_available_governors(cpu);
	if (governors) {
		printf(gettext ("  available cpufreq governors: "));
		while (governors->next) {
			printf("%s, ", governors->governor);
			governors = governors->next;
		}
		printf("%s\n", governors->governor);
		cpufreq_put_available_governors(governors);
	}

	policy = cpufreq_get_policy(cpu);
	if (policy) {
		printf(gettext ("  current policy: frequency should be within "));
		print_speed(policy->min);
		printf(gettext (" and "));
		print_speed(policy->max);

		printf(".\n                  ");
		printf(gettext ("The governor \"%s\" may"
		       " decide which speed to use\n                  within this range.\n"),
		       policy->governor);
		cpufreq_put_policy(policy);
	}

	if (freq_kernel || freq_hardware) {
		printf(gettext ("  current CPU frequency is "));
		if (freq_hardware) {
			print_speed(freq_hardware);
			printf(gettext (" (asserted by call to hardware)"));
		}
		else
			print_speed(freq_kernel);
		printf(".\n");
	}
	stats = cpufreq_get_stats(cpu, &total_time);
	if (stats) {
		printf(gettext ("  cpufreq stats: "));
		while (stats) {
			print_speed(stats->frequency);
			printf(":%.2f%%", (100.0 * stats->time_in_state) / total_time);
			stats = stats->next;
			if (stats)
				printf(", ");
		}
		cpufreq_put_stats(stats);
		total_trans = cpufreq_get_transitions(cpu);
		if (total_trans)
			printf("  (%lu)\n", total_trans);
		else
			printf("\n");
	}
}

static void debug_output(unsigned int cpu, unsigned int all) {
	if (all) {
		unsigned int nr_cpus = count_cpus();
		for (cpu=0; cpu < nr_cpus; cpu++) {
			if (cpufreq_cpu_exists(cpu))
				continue;
			debug_output_one(cpu);
		}
	} else
		debug_output_one(cpu);
}


/* --freq / -f */

static int get_freq_kernel(unsigned int cpu, unsigned int human) {
	unsigned long freq = cpufreq_get_freq_kernel(cpu);
	if (!freq)
		return -EINVAL;
	if (human) {
		print_speed(freq);
		printf("\n");
	} else
		printf("%lu\n", freq);
	return 0;
}


/* --hwfreq / -w */

static int get_freq_hardware(unsigned int cpu, unsigned int human) {
	unsigned long freq = cpufreq_get_freq_hardware(cpu);
	if (!freq)
		return -EINVAL;
	if (human) {
		print_speed(freq);
		printf("\n");
	} else
		printf("%lu\n", freq);
	return 0;
}

/* --hwlimits / -l */

static int get_hardware_limits(unsigned int cpu) {
	unsigned long min, max;
	if (cpufreq_get_hardware_limits(cpu, &min, &max))
		return -EINVAL;
	printf("%lu %lu\n", min, max);
	return 0;
}

/* --driver / -d */

static int get_driver(unsigned int cpu) {
	char *driver = cpufreq_get_driver(cpu);
	if (!driver)
		return -EINVAL;
	printf("%s\n", driver);
	cpufreq_put_driver(driver);
	return 0;
}

/* --policy / -p */

static int get_policy(unsigned int cpu) {
	struct cpufreq_policy *policy = cpufreq_get_policy(cpu);
	if (!policy)
		return -EINVAL;
	printf("%lu %lu %s\n", policy->min, policy->max, policy->governor);
	cpufreq_put_policy(policy);
	return 0;
}

/* --governors / -g */

static int get_available_governors(unsigned int cpu) {
	struct cpufreq_available_governors *governors = cpufreq_get_available_governors(cpu);
	if (!governors)
		return -EINVAL;

	while (governors->next) {
		printf("%s ", governors->governor);
		governors = governors->next;
	}
	printf("%s\n", governors->governor);
	cpufreq_put_available_governors(governors);
	return 0;
}


/* --affected-cpus  / -a */

static int get_affected_cpus(unsigned int cpu) {
	struct cpufreq_affected_cpus *cpus = cpufreq_get_affected_cpus(cpu);
	if (!cpus)
		return -EINVAL;

	while (cpus->next) {
		printf("%d ", cpus->cpu);
		cpus = cpus->next;
	}
	printf("%d\n", cpus->cpu);
	cpufreq_put_affected_cpus(cpus);
	return 0;
}

/* --stats / -s */

static int get_freq_stats(unsigned int cpu, unsigned int human) {
	unsigned long total_trans = cpufreq_get_transitions(cpu);
	unsigned long long total_time;
	struct cpufreq_stats *stats = cpufreq_get_stats(cpu, &total_time);
	while (stats) {
		if (human) {
			print_speed(stats->frequency);
			printf(":%.2f%%", (100.0 * stats->time_in_state) / total_time);
		}
		else
			printf("%lu:%llu", stats->frequency, stats->time_in_state);
		stats = stats->next;
		if (stats)
			printf(", ");
	}
	cpufreq_put_stats(stats);
	if (total_trans)
		printf("  (%lu)\n", total_trans);
	return 0;
}

static void print_header(void) {
	printf(PACKAGE " " VERSION ": cpufreq-info (C) Dominik Brodowski 2004-2006\n");
	printf(gettext ("Report errors and bugs to %s, please.\n"), PACKAGE_BUGREPORT);
}

static void print_help(void) {
	printf(gettext ("Usage: cpufreq-info [options]\n"));
	printf(gettext ("Options:\n"));
	printf(gettext ("  -c CPU, --cpu CPU    CPU number which information shall be determined about\n"));
	printf(gettext ("  -e, --debug          Prints out debug information\n"));
	printf(gettext ("  -f, --freq           Get frequency the CPU currently runs at, according\n"
	       "                       to the cpufreq core *\n"));
	printf(gettext ("  -w, --hwfreq         Get frequency the CPU currently runs at, by reading\n"
	       "                       it from hardware (only available to root) *\n"));
	printf(gettext ("  -l, --hwlimits       Determine the minimum and maximum CPU frequency allowed *\n"));
	printf(gettext ("  -d, --driver         Determines the used cpufreq kernel driver *\n"));
	printf(gettext ("  -p, --policy         Gets the currently used cpufreq policy *\n"));
	printf(gettext ("  -g, --governors      Determines available cpufreq governors *\n"));
	printf(gettext ("  -a, --affected-cpus  Determines which CPUs can only switch frequency at the\n"
			"                       same time *\n"));
	printf(gettext ("  -s, --stats          Shows cpufreq statistics if available\n"));
	printf(gettext ("  -o, --proc           Prints out information like provided by the /proc/cpufreq\n"
	       "                       interface in 2.4. and early 2.6. kernels\n"));
	printf(gettext ("  -m, --human          human-readable output for the -f, -w and -s parameters\n"));
	printf(gettext ("  -h, --help           Prints out this screen\n"));

	printf("\n");
	printf(gettext ("If no argument or only the -c, --cpu parameter is given, debug output about\n"
	       "cpufreq is printed which is useful e.g. for reporting bugs.\n"));
	printf(gettext ("For the arguments marked with *, omitting the -c or --cpu argument is\n"
	"equivalent to setting it to zero\n"));
}

static struct option info_opts[] = {
	{ .name="cpu",		.has_arg=required_argument,	.flag=NULL,	.val='c'},
	{ .name="debug",	.has_arg=no_argument,		.flag=NULL,	.val='e'},
	{ .name="freq",		.has_arg=no_argument,		.flag=NULL,	.val='f'},
	{ .name="hwfreq",	.has_arg=no_argument,		.flag=NULL,	.val='w'},
	{ .name="hwlimits",	.has_arg=no_argument,		.flag=NULL,	.val='l'},
	{ .name="driver",	.has_arg=no_argument,		.flag=NULL,	.val='d'},
	{ .name="policy",	.has_arg=no_argument,		.flag=NULL,	.val='p'},
	{ .name="governors",	.has_arg=no_argument,		.flag=NULL,	.val='g'},
	{ .name="affected-cpus",.has_arg=no_argument,		.flag=NULL,	.val='a'},
	{ .name="stats",	.has_arg=no_argument,		.flag=NULL,	.val='s'},
	{ .name="proc",		.has_arg=no_argument,		.flag=NULL,	.val='o'},
	{ .name="human",	.has_arg=no_argument,		.flag=NULL,	.val='m'},
	{ .name="help",		.has_arg=no_argument,		.flag=NULL,	.val='h'},
};

int main(int argc, char **argv) {
	extern char *optarg;
	extern int optind, opterr, optopt;
	int ret = 0, cont = 1;
	unsigned int cpu = 0;
	unsigned int cpu_defined = 0;
	unsigned int human = 0;
	int output_param = 0;

	setlocale(LC_ALL, "");
	textdomain (PACKAGE);

	do {
		ret = getopt_long(argc, argv, "c:hoefwldpgasm", info_opts, NULL);
		switch (ret) {
		case '?':
			output_param = '?';
			cont = 0;
			break;
		case 'h':
			output_param = 'h';
			cont = 0;
			break;
		case -1:
			cont = 0;
			break;
		case 'o':
		case 'a':
		case 'g':
		case 'p':
		case 'd':
		case 'l':
		case 'w':
		case 'f':
		case 'e':
		case 's':
			if (output_param) {
				output_param = -1;
				cont = 0;
				break;
			}
			output_param = ret;
			break;
		case 'c':
			if (cpu_defined) {
				output_param = -1;
				cont = 0;
				break;
			}
			if ((sscanf(optarg, "%d ", &cpu)) != 1) {
				output_param = '?';
				cont = 0;
			}
			cpu_defined = 1;
			break;
		case 'm':
			if (human) {
				output_param = -1;
				cont = 0;
				break;
			}
			human = 1;
			break;
		}
	} while(cont);

	switch (output_param) {
	case 'o':
		if (cpu_defined) {
			print_header();
			printf(gettext ("The argument passed to this tool can't be combined with passing a --cpu argument\n"));
			return -EINVAL;
		}
		break;
	case 0:
		output_param = 'e';
	}

	ret = 0;

	switch (output_param) {
	case -1:
		print_header();
		printf(gettext ("You can't specify more than one --cpu parameter and/or\n"
		       "more than one output-specific argument\n"));
		return -EINVAL;
		break;
	case '?':
		print_header();
		printf(gettext ("invalid or unknown argument\n"));
		print_help();
		ret = -EINVAL;
		break;
	case 'h':
		print_header();
		print_help();
		break;
	case 'o':
		proc_cpufreq_output();
		break;
	case 'e':
		print_header();
		debug_output(cpu, !(cpu_defined));
		break;
	case 'a':
		ret = get_affected_cpus(cpu);
		break;
	case 'g':
		ret = get_available_governors(cpu);
		break;
	case 'p':
		ret = get_policy(cpu);
		break;
	case 'd':
		ret = get_driver(cpu);
		break;
	case 'l':
		ret = get_hardware_limits(cpu);
		break;
	case 'w':
		ret = get_freq_hardware(cpu, human);
		break;
	case 'f':
		ret = get_freq_kernel(cpu, human);
		break;
	case 's':
		ret = get_freq_stats(cpu, human);
		break;
	}
	return (ret);
}
