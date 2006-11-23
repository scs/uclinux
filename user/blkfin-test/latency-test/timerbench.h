
#ifndef _TIMERBENCH_H
#define _TIMERBENCH_H

typedef struct rttst_bench_res {
    long long               avg;
    long                    min;
    long                    max;
    long                    overruns;
    long                    test_loops;
} rttst_bench_res_t;

typedef struct rttst_interm_bench_res {
    struct rttst_bench_res  last;
    struct rttst_bench_res  overall;
} rttst_interm_bench_res_t;

typedef struct rttst_overall_bench_res {
    struct rttst_bench_res  result;
    long                    *histogram_avg;
    long                    *histogram_min;
    long                    *histogram_max;
} rttst_overall_bench_res_t;


typedef struct rttst_tmbench_config {
    int                     mode;
    unsigned long long                period;
    int                     priority;
    int                     warmup_loops;
    int                     histogram_size;
    int                     histogram_bucketsize;
    int                     freeze_max;
} rttst_tmbench_config_t;

struct timer_info {
    long long start_tsc;
    long long period_tsc;
};

#define TB_MAJOR 222
#define TB_DEVNAME "Timer Bench"

#define RTTST_TMBENCH_TASK       0
#define RTTST_TMBENCH_HANDLER    1

#define RTTST_RTIOC_INTERM_BENCH_RES \
       	_IOWR(0x1, 0x00, struct rttst_interm_bench_res)


#define RTTST_RTIOC_TMBENCH_START \
	    _IOW(0x1, 0x10, struct rttst_tmbench_config)

#define RTTST_RTIOC_TMBENCH_STOP \
	    _IOWR(0x1, 0x11, struct rttst_overall_bench_res)

#define RTTST_GETCCLK \
	    _IOWR(0x1, 0x01, unsigned long)

#define RTTST_GETSCLK \
	    _IOWR(0x1, 0x02, unsigned long)

#define RTTST_TMR_START \
	_IOW(0x1, 0x3, long)

#define RTTST_TMR_WAIT \
	_IO(0x1, 0x4)

#define RTTST_TMR_STOP \
	_IO(0x1, 0x5)

#endif
