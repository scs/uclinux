/**
 * @file
 * Real-Time Driver Model for Xenomai, testing device profile header
 *
 * @note Copyright (C) 2005 Jan Kiszka <jan.kiszka@web.de>
 *
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * @ingroup rttesting
 */

/*!
 * @ingroup profiles
 * @defgroup rttesting Testing Devices
 *
 * This group of devices is intended to provide in-kernel testing results.
 * Feel free to comment on this profile via the Xenomai mailing list
 * (xenomai-core@gna.org) or directly to the author (jan.kiszka@web.de).
 *
 * @b Profile @b Revision: 1
 * @n
 * @n
 * @par Device Characteristics
 * @ref rtdm_device.device_flags "Device Flags": @c RTDM_NAMED_DEVICE @n
 * @n
 * @ref rtdm_device.device_name "Device Name": @c "rttest<N>", N >= 0 @n
 * @n
 * @ref rtdm_device.device_class "Device Class": @c RTDM_CLASS_TESTING @n
 * @n
 *
 * @par Supported Operations
 * @b Open @n
 * Environments: non-RT (RT optional)@n
 * Specific return values: none @n
 * @n
 * @b Close @n
 * Environments: non-RT (RT optional)@n
 * Specific return values: none @n
 * @n
 * @b IOCTL @n
 * Mandatory Environments: see @ref TSTIOCTLs below @n
 * Specific return values: see @ref TSTIOCTLs below @n
 *
 * @{
 */

#ifndef _RTTESTING_H
#define _RTTESTING_H

#include <rtdm/rtdm.h>

#define RTTST_PROFILE_VER		1

typedef struct rttst_bench_res {
	long long avg;
	long min;
	long max;
	long overruns;
	long test_loops;
} rttst_bench_res_t;

typedef struct rttst_interm_bench_res {
	struct rttst_bench_res last;
	struct rttst_bench_res overall;
} rttst_interm_bench_res_t;

typedef struct rttst_overall_bench_res {
	struct rttst_bench_res result;
	long *histogram_avg;
	long *histogram_min;
	long *histogram_max;
	void *__padding;	/* align to dwords on 32-bit archs */
} rttst_overall_bench_res_t;

#define RTTST_TMBENCH_NONE		-1
#define RTTST_TMBENCH_TASK		0
#define RTTST_TMBENCH_HANDLER		1

typedef struct rttst_tmbench_config {
	int mode;
	int priority;
	nanosecs_rel_t period;
	int warmup_loops;
	int histogram_size;
	int histogram_bucketsize;
	int freeze_max;
} rttst_tmbench_config_t;

#define RTTST_IRQBENCH_USER_TASK	0
#define RTTST_IRQBENCH_KERNEL_TASK	1
#define RTTST_IRQBENCH_HANDLER		2
#define RTTST_IRQBENCH_HARD_IRQ		3

#define RTTST_IRQBENCH_SERPORT		0
#define RTTST_IRQBENCH_PARPORT		1

typedef struct rttst_irqbench_config {
	int mode;
	int priority;
	int calibration_loops;
	unsigned int port_type;
	unsigned long port_ioaddr;
	unsigned int port_irq;
} rttst_irqbench_config_t;

typedef struct rttst_irqbench_stats {
	unsigned long long irqs_received;
	unsigned long long irqs_acknowledged;
} rttst_irqbench_stats_t;

#define RTTST_SWTEST_FPU		0x1
#define RTTST_SWTEST_USE_FPU		0x2 /* Only for kernel-space tasks. */

struct rttst_swtest_task {
	unsigned index;
	unsigned flags;
};

struct rttst_swtest_dir {
	unsigned from;
	unsigned to;
};

struct rttst_swtest_error {
	struct rttst_swtest_dir last_switch;
	unsigned fp_val;
};

#define RTIOC_TYPE_TESTING		RTDM_CLASS_TESTING

/*!
 * @name Sub-Classes of RTDM_CLASS_TESTING
 * @{ */
#define RTDM_SUBCLASS_TIMERBENCH	0
#define RTDM_SUBCLASS_IRQBENCH		1
#define RTDM_SUBCLASS_SWITCHTEST	2
/** @} */

/*!
 * @anchor TSTIOCTLs @name IOCTLs
 * Testing device IOCTLs
 * @{ */
#define RTTST_RTIOC_INTERM_BENCH_RES \
	_IOWR(RTIOC_TYPE_TESTING, 0x00, struct rttst_interm_bench_res)

#define RTTST_RTIOC_TMBENCH_START \
	_IOW(RTIOC_TYPE_TESTING, 0x10, struct rttst_tmbench_config)

#define RTTST_RTIOC_TMBENCH_STOP \
	_IOWR(RTIOC_TYPE_TESTING, 0x11, struct rttst_overall_bench_res)

#define RTTST_RTIOC_IRQBENCH_START \
	_IOW(RTIOC_TYPE_TESTING, 0x20, struct rttst_irqbench_config)

#define RTTST_RTIOC_IRQBENCH_STOP \
	_IO(RTIOC_TYPE_TESTING, 0x21)

#define RTTST_RTIOC_IRQBENCH_GET_STATS \
	_IOR(RTIOC_TYPE_TESTING, 0x22, struct rttst_irqbench_stats)

#define RTTST_RTIOC_IRQBENCH_WAIT_IRQ \
	_IO(RTIOC_TYPE_TESTING, 0x23)

#define RTTST_RTIOC_IRQBENCH_REPLY_IRQ \
	_IO(RTIOC_TYPE_TESTING, 0x24)

#define RTTST_RTIOC_SWTEST_SET_TASKS_COUNT \
	_IOW(RTIOC_TYPE_TESTING, 0x30, unsigned long)

#define RTTST_RTIOC_SWTEST_SET_CPU \
	_IOW(RTIOC_TYPE_TESTING, 0x31, unsigned long)

#define RTTST_RTIOC_SWTEST_REGISTER_UTASK \
	_IOW(RTIOC_TYPE_TESTING, 0x32, struct rttst_swtest_task)

#define RTTST_RTIOC_SWTEST_CREATE_KTASK \
	_IOWR(RTIOC_TYPE_TESTING, 0x33, struct rttst_swtest_task)

#define RTTST_RTIOC_SWTEST_PEND \
	_IOR(RTIOC_TYPE_TESTING, 0x34, struct rttst_swtest_task)

#define RTTST_RTIOC_SWTEST_SWITCH_TO \
	_IOR(RTIOC_TYPE_TESTING, 0x35, struct rttst_swtest_dir)

#define RTTST_RTIOC_SWTEST_GET_SWITCHES_COUNT \
	_IOR(RTIOC_TYPE_TESTING, 0x36, unsigned long)

#define RTTST_RTIOC_SWTEST_GET_LAST_ERROR \
	_IOR(RTIOC_TYPE_TESTING, 0x37, struct rttst_swtest_error)

#define RTTST_RTIOC_SWTEST_SET_PAUSE \
	_IOW(RTIOC_TYPE_TESTING, 0x38, unsigned long)
/** @} */

/** @} */

#endif /* _RTTESTING_H */
