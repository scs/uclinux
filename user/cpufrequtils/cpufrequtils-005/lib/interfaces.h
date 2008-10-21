#ifdef INTERFACE_SYSFS

extern unsigned int sysfs_cpu_exists(unsigned int cpu);
extern unsigned long sysfs_get_freq_kernel(unsigned int cpu);
extern unsigned long sysfs_get_freq_hardware(unsigned int cpu);
extern int sysfs_get_hardware_limits(unsigned int cpu, unsigned long *min, unsigned long *max);
extern char * sysfs_get_driver(unsigned int cpu);
extern struct cpufreq_policy * sysfs_get_policy(unsigned int cpu);
extern struct cpufreq_available_governors * sysfs_get_available_governors(unsigned int cpu);
extern struct cpufreq_available_frequencies * sysfs_get_available_frequencies(unsigned int cpu);
extern struct cpufreq_affected_cpus * sysfs_get_affected_cpus(unsigned int cpu);
extern struct cpufreq_stats * sysfs_get_stats(unsigned int cpu, unsigned long long *total_time);
extern unsigned long sysfs_get_transitions(unsigned int cpu);
extern int sysfs_set_policy(unsigned int cpu, struct cpufreq_policy *policy);
extern int sysfs_modify_policy_min(unsigned int cpu, unsigned long min_freq);
extern int sysfs_modify_policy_max(unsigned int cpu, unsigned long max_freq);
extern int sysfs_modify_policy_governor(unsigned int cpu, char *governor);
extern int sysfs_set_frequency(unsigned int cpu, unsigned long target_frequency);

#else

static inline unsigned int sysfs_cpu_exists(unsigned int cpu) { return -ENOSYS; }
static inline unsigned long sysfs_get_freq_kernel(unsigned int cpu) { return 0; }
static inline unsigned long sysfs_get_freq_hardware(unsigned int cpu) { return 0; }
static inline int sysfs_get_hardware_limits(unsigned int cpu, unsigned long *min, unsigned long *max)  { return -ENOSYS; }
static inline char * sysfs_get_driver(unsigned int cpu) { return NULL; }
static inline struct cpufreq_policy * sysfs_get_policy(unsigned int cpu) { return NULL; }
static inline struct cpufreq_available_governors * sysfs_get_available_governors(unsigned int cpu) { return NULL; }
static inline struct cpufreq_available_frequencies * sysfs_get_available_frequencies(unsigned int cpu) { return NULL; }
static inline struct cpufreq_affected_cpus * sysfs_get_affected_cpus(unsigned int cpu) { return NULL; }
static inline struct cpufreq_stats * sysfs_get_stats(unsigned int cpu, unsigned long long *total_time) { return NULL; }
static inline unsigned long sysfs_get_transitions(unsigned int cpu) { return 0; }
static inline int sysfs_set_policy(unsigned int cpu, struct cpufreq_policy *policy) { return -ENOSYS; }
static inline int sysfs_modify_policy_min(unsigned int cpu, unsigned long min_freq) { return -ENOSYS; }
static inline int sysfs_modify_policy_max(unsigned int cpu, unsigned long max_freq) { return -ENOSYS; }
static inline int sysfs_modify_policy_governor(unsigned int cpu, char *governor) { return -ENOSYS; }
static inline int sysfs_set_frequency(unsigned int cpu, unsigned long target_frequency) { return -ENOSYS; }

#endif


#ifdef INTERFACE_PROC

extern int proc_cpu_exists(unsigned int cpu);
extern unsigned long proc_get_freq_kernel(unsigned int cpu);
extern struct cpufreq_policy * proc_get_policy(unsigned int cpu);
extern int proc_set_policy(unsigned int cpu, struct cpufreq_policy *policy);
extern int proc_set_frequency(unsigned int cpu, unsigned long target_frequency);
#else

static inline int proc_cpu_exists(unsigned int cpu) {return -ENOSYS; }
static inline unsigned long proc_get_freq_kernel(unsigned int cpu) { return 0; }
static inline struct cpufreq_policy * proc_get_policy(unsigned int cpu) { return NULL; }
static inline int proc_set_policy(unsigned int cpu, struct cpufreq_policy *policy) { return -ENOSYS; }
static inline int proc_set_frequency(unsigned int cpu, unsigned long target_frequency) { return -ENOSYS; }

#endif

/* these aren't implemented in /proc, and probably never will...*/

static inline unsigned long proc_get_freq_hardware(unsigned int cpu) { return 0; }
static inline int proc_get_hardware_limits(unsigned int cpu, unsigned long *min, unsigned long *max)  { return -ENOSYS; }
static inline char * proc_get_driver(unsigned int cpu) {return NULL; }
static inline struct cpufreq_available_governors * proc_get_available_governors(unsigned int cpu) { return NULL; }
static inline struct cpufreq_available_frequencies * proc_get_available_frequencies(unsigned int cpu) { return NULL; }
static inline struct cpufreq_affected_cpus * proc_get_affected_cpus(unsigned int cpu) { return NULL; }
static inline int proc_modify_policy_min(unsigned int cpu, unsigned long min_freq) { return -ENOSYS; }
static inline int proc_modify_policy_max(unsigned int cpu, unsigned long max_freq) { return -ENOSYS; }
static inline int proc_modify_policy_governor(unsigned int cpu, char *governor) { return -ENOSYS; }
