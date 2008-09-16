#include <nucleus/synch.h>
#include <nucleus/thread.h>
#include <rtdm/rttesting.h>
#include <rtdm/rtdm_driver.h>
#include <asm/xenomai/fptest.h>
#include <asm/semaphore.h>

#define RTSWITCH_RT      0x4
#define RTSWITCH_NRT     0
#define RTSWITCH_KERNEL  0x8

typedef struct {
	struct rttst_swtest_task base;
	xnsynch_t rt_synch;
	struct semaphore nrt_synch;
	xnthread_t ktask;          /* For kernel-space real-time tasks. */
} rtswitch_task_t;

typedef struct rtswitch_context {
	rtswitch_task_t *tasks;
	unsigned tasks_count;
	unsigned next_index;
	struct semaphore lock;
	unsigned cpu;
	unsigned switches_count;

	unsigned failed;
	struct rttst_swtest_error error;
} rtswitch_context_t;

static unsigned int start_index;

module_param(start_index, uint, 0400);
MODULE_PARM_DESC(start_index, "First device instance number to be used");

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gilles.Chanteperdrix@laposte.net");

static rtswitch_task_t *rtswitch_utask[NR_CPUS];
static rtdm_nrtsig_t rtswitch_wake_utask;

static int rtswitch_pend_rt(rtswitch_context_t *ctx,
                            unsigned idx)
{
	rtswitch_task_t *task;

	if (idx > ctx->tasks_count)
		return -EINVAL;

	task = &ctx->tasks[idx];
	task->base.flags |= RTSWITCH_RT;

	xnsynch_sleep_on(&task->rt_synch, XN_INFINITE, XN_RELATIVE);

	if (xnthread_test_info(xnpod_current_thread(), XNBREAK))
		return -EINTR;

	if (xnthread_test_info(xnpod_current_thread(), XNRMID))
		return -EIDRM;

	if (ctx->failed)
		return 1;

	return 0;
}

static int rtswitch_to_rt(rtswitch_context_t *ctx,
			  unsigned from_idx,
			  unsigned to_idx)
{
	rtswitch_task_t *from, *to;
	spl_t s;

	if (from_idx > ctx->tasks_count || to_idx > ctx->tasks_count)
		return -EINVAL;

	from = &ctx->tasks[from_idx];
	to = &ctx->tasks[to_idx];

	from->base.flags |= RTSWITCH_RT;
	++ctx->switches_count;
	ctx->error.last_switch.from = from_idx;
	ctx->error.last_switch.to = to_idx;

	switch (to->base.flags & RTSWITCH_RT) {
	case RTSWITCH_NRT:
		rtswitch_utask[ctx->cpu] = to;
		rtdm_nrtsig_pend(&rtswitch_wake_utask);
		xnlock_get_irqsave(&nklock, s);
		break;

	case RTSWITCH_RT:
		xnlock_get_irqsave(&nklock, s);

		xnsynch_wakeup_one_sleeper(&to->rt_synch);
		break;

	default:
		return -EINVAL;
	}

	xnsynch_sleep_on(&from->rt_synch, XN_INFINITE, XN_RELATIVE);

	xnlock_put_irqrestore(&nklock, s);

	if (xnthread_test_info(xnpod_current_thread(), XNBREAK))
		return -EINTR;

	if (xnthread_test_info(xnpod_current_thread(), XNRMID))
		return -EIDRM;

	if (ctx->failed)
		return 1;

	return 0;
}

static int rtswitch_pend_nrt(rtswitch_context_t *ctx,
                             unsigned idx)
{
	rtswitch_task_t *task;

	if (idx > ctx->tasks_count)
		return -EINVAL;

	task = &ctx->tasks[idx];

	task->base.flags &= ~RTSWITCH_RT;

	if (down_interruptible(&task->nrt_synch))
		return -EINTR;

	if (ctx->failed)
		return 1;

	return 0;
}

static int rtswitch_to_nrt(rtswitch_context_t *ctx,
			   unsigned from_idx,
			   unsigned to_idx)
{
	rtswitch_task_t *from, *to;

	if (from_idx > ctx->tasks_count || to_idx > ctx->tasks_count)
		return -EINVAL;

	from = &ctx->tasks[from_idx];
	to = &ctx->tasks[to_idx];

	from->base.flags &= ~RTSWITCH_RT;
	++ctx->switches_count;
	ctx->error.last_switch.from = from_idx;
	ctx->error.last_switch.to = to_idx;

	switch (to->base.flags & RTSWITCH_RT) {
	case RTSWITCH_NRT:
		up(&to->nrt_synch);
		break;

	case RTSWITCH_RT:
		xnsynch_wakeup_one_sleeper(&to->rt_synch);
		xnpod_schedule();
		break;

	default:
		return -EINVAL;
	}

	if (down_interruptible(&from->nrt_synch))
		return -EINTR;

	if (ctx->failed)
		return 1;

	return 0;
}

static int rtswitch_set_tasks_count(rtswitch_context_t *ctx, unsigned count)
{
	rtswitch_task_t *tasks;

	if (ctx->tasks_count == count)
		return 0;

	tasks = kmalloc(count * sizeof(*tasks), GFP_KERNEL);

	if (!tasks)
		return -ENOMEM;

	down(&ctx->lock);

	if (ctx->tasks)
		kfree(ctx->tasks);

	ctx->tasks = tasks;
	ctx->tasks_count = count;
	ctx->next_index = 0;

	up(&ctx->lock);

	return 0;
}

static int rtswitch_register_task(rtswitch_context_t *ctx,
                                  struct rttst_swtest_task *arg)
{
	rtswitch_task_t *t;

	down(&ctx->lock);

	if (ctx->next_index == ctx->tasks_count) {
		up(&ctx->lock);
		return -EBUSY;
	}

	arg->index = ctx->next_index;
	t = &ctx->tasks[arg->index];
	ctx->next_index++;
	t->base = *arg;
	sema_init(&t->nrt_synch, 0);
	xnsynch_init(&t->rt_synch, XNSYNCH_FIFO);

	up(&ctx->lock);

	return 0;
}

struct taskarg {
	rtswitch_context_t *ctx;
	rtswitch_task_t *task;
};

static void handle_ktask_error(rtswitch_context_t *ctx, unsigned fp_val)
{
	unsigned i;
	
	ctx->failed = 1;
	ctx->error.fp_val = fp_val;

	for (i = 0; i < ctx->tasks_count; i++) {
		rtswitch_task_t *task = &ctx->tasks[i];

		/* Find the first non kernel-space task. */
		if ((task->base.flags & RTSWITCH_KERNEL))
			continue;

		/* Unblock it. */
		switch(task->base.flags & RTSWITCH_RT) {
		case RTSWITCH_NRT:
			rtswitch_utask[ctx->cpu] = task;
			rtdm_nrtsig_pend(&rtswitch_wake_utask);
			break;

		case RTSWITCH_RT:
			xnsynch_wakeup_one_sleeper(&task->rt_synch);
			break;
		}

		xnpod_suspend_self();
	}
}

static void rtswitch_ktask(void *cookie)
{
	struct taskarg *arg = (struct taskarg *) cookie;
	rtswitch_context_t *ctx = arg->ctx;
	rtswitch_task_t *task = arg->task;
	unsigned to, i = 0;

	to = task->base.index;

	rtswitch_pend_rt(ctx, task->base.index);

	for(;;) {
		if (++to == task->base.index)
			++to;
		if (to > ctx->tasks_count - 1)
			to = 0;
		if (to == task->base.index)
			++to;

		if (task->base.flags & RTTST_SWTEST_USE_FPU)
			fp_regs_set(task->base.index + i * 1000);
		rtswitch_to_rt(ctx, task->base.index, to);
		if (task->base.flags & RTTST_SWTEST_USE_FPU) {
			unsigned fp_val, expected;

			expected = task->base.index + i * 1000;
			fp_val = fp_regs_check(expected);

			if (fp_val != expected)
				handle_ktask_error(ctx, fp_val);
		}
				
		if (++i == 4000000)
			i = 0;
	}
}

static int rtswitch_create_ktask(rtswitch_context_t *ctx,
                                 struct rttst_swtest_task *ptask)
{
	rtswitch_task_t *task;
	xnflags_t init_flags;
	struct taskarg arg;
	char name[30];
	int err;

	ptask->flags |= RTSWITCH_KERNEL;
	err = rtswitch_register_task(ctx, ptask);

	if (err)
		return err;

	snprintf(name, sizeof(name), "rtk%d/%u", ptask->index, ctx->cpu);

	task = &ctx->tasks[ptask->index];

	arg.ctx = ctx;
	arg.task = task;

	init_flags = (ptask->flags & RTTST_SWTEST_FPU) ? XNFPU : 0;

	/* Migrate the calling thread to the same CPU as the created task, in
	   order to be sure that the created task is suspended when this function
	   returns. This also allow us to use the stack to pass the parameters to
	   the created task. */
	set_cpus_allowed(current, cpumask_of_cpu(ctx->cpu));

	err = xnpod_init_thread(&task->ktask, rtdm_tbase, name, 1, init_flags, 0, NULL);

	if (!err)
		err = xnpod_start_thread(&task->ktask,
					 0,
					 0,
					 xnarch_cpumask_of_cpu(ctx->cpu),
					 rtswitch_ktask,
					 &arg);
	else
		/* In order to avoid calling xnpod_delete_thread with invalid
		   thread. */
		task->base.flags = 0;

	/* Putting the argument on stack is safe, because the new thread will
	   preempt the current thread immediately, and will suspend only once the
	   arguments on stack are used. */

	return err;
}

static int rtswitch_open(struct rtdm_dev_context *context,
                         rtdm_user_info_t *user_info,
                         int oflags)
{
	rtswitch_context_t *ctx = (rtswitch_context_t *) context->dev_private;

	ctx->tasks = NULL;
	ctx->tasks_count = ctx->next_index = ctx->cpu = ctx->switches_count = 0;
	init_MUTEX(&ctx->lock);
	ctx->failed = 0;
	ctx->error.last_switch.from = ctx->error.last_switch.to = -1;

	return 0;
}

static int rtswitch_close(struct rtdm_dev_context *context,
                          rtdm_user_info_t *user_info)
{
	rtswitch_context_t *ctx = (rtswitch_context_t *) context->dev_private;
	unsigned i;

	if (ctx->tasks) {
		set_cpus_allowed(current, cpumask_of_cpu(ctx->cpu));

		for (i = 0; i < ctx->next_index; i++) {
			rtswitch_task_t *task = &ctx->tasks[i];

			if (task->base.flags & RTSWITCH_KERNEL)
				xnpod_delete_thread(&task->ktask);
			xnsynch_destroy(&task->rt_synch);
		}
		xnpod_schedule();
		kfree(ctx->tasks);
	}

	return 0;
}

static int rtswitch_ioctl_nrt(struct rtdm_dev_context *context,
                              rtdm_user_info_t *user_info,
                              unsigned int request,
                              void *arg)
{
	rtswitch_context_t *ctx = (rtswitch_context_t *) context->dev_private;
	struct rttst_swtest_task task;
	struct rttst_swtest_dir fromto;
	unsigned long count;
	int err;

	switch (request)
		{
		case RTTST_RTIOC_SWTEST_SET_TASKS_COUNT:
			return rtswitch_set_tasks_count(ctx,
							(unsigned long) arg);

		case RTTST_RTIOC_SWTEST_SET_CPU:
			if ((unsigned long) arg > xnarch_num_online_cpus() - 1)
				return -EINVAL;

			ctx->cpu = (unsigned long) arg;
			return 0;

		case RTTST_RTIOC_SWTEST_REGISTER_UTASK:
			if (!rtdm_rw_user_ok(user_info, arg, sizeof(task)))
				return -EFAULT;

			rtdm_copy_from_user(user_info, &task, arg, sizeof(task));

			err = rtswitch_register_task(ctx, &task);

			if (!err)
				rtdm_copy_to_user(user_info,
						  arg,
						  &task,
						  sizeof(task));

			return err;

		case RTTST_RTIOC_SWTEST_CREATE_KTASK:
			if (!rtdm_rw_user_ok(user_info, arg, sizeof(task)))
				return -EFAULT;

			rtdm_copy_from_user(user_info, &task, arg, sizeof(task));

			err = rtswitch_create_ktask(ctx, &task);

			if (!err)
				rtdm_copy_to_user(user_info,
						  arg,
						  &task,
						  sizeof(task));

			return err;

		case RTTST_RTIOC_SWTEST_PEND:
			if (!rtdm_read_user_ok(user_info, arg, sizeof(task)))
				return -EFAULT;

			rtdm_copy_from_user(user_info, &task, arg, sizeof(task));

			return rtswitch_pend_nrt(ctx, task.index);

		case RTTST_RTIOC_SWTEST_SWITCH_TO:
			if (!rtdm_read_user_ok(user_info, arg, sizeof(fromto)))
				return -EFAULT;

			rtdm_copy_from_user(user_info,
					    &fromto,
					    arg,
					    sizeof(fromto));

			return rtswitch_to_nrt(ctx, fromto.from, fromto.to);

		case RTTST_RTIOC_SWTEST_GET_SWITCHES_COUNT:
			if (!rtdm_rw_user_ok(user_info, arg, sizeof(count)))
				return -EFAULT;

			count = ctx->switches_count;

			rtdm_copy_to_user(user_info, arg, &count, sizeof(count));

			return 0;

		case RTTST_RTIOC_SWTEST_GET_LAST_ERROR:
			if (!rtdm_rw_user_ok(user_info, arg, sizeof(ctx->error)))
				return -EFAULT;

			rtdm_copy_to_user(user_info,
					  arg,
					  &ctx->error,
					  sizeof(ctx->error));

			return 0;

		default:
			return -ENOTTY;
		}
}

static int rtswitch_ioctl_rt(struct rtdm_dev_context *context,
                             rtdm_user_info_t *user_info,
                             unsigned int request,
                             void *arg)
{
	rtswitch_context_t *ctx = (rtswitch_context_t *) context->dev_private;
	struct rttst_swtest_task task;
	struct rttst_swtest_dir fromto;

	switch (request)
		{
		case RTTST_RTIOC_SWTEST_REGISTER_UTASK:
		case RTTST_RTIOC_SWTEST_CREATE_KTASK:
		case RTTST_RTIOC_SWTEST_GET_SWITCHES_COUNT:
			return -ENOSYS;

		case RTTST_RTIOC_SWTEST_PEND:
			if (!rtdm_read_user_ok(user_info, arg, sizeof(task)))
				return -EFAULT;

			rtdm_copy_from_user(user_info, &task, arg, sizeof(task));

			return rtswitch_pend_rt(ctx, task.index);

		case RTTST_RTIOC_SWTEST_SWITCH_TO:
			if (!rtdm_read_user_ok(user_info, arg, sizeof(fromto)))
				return -EFAULT;

			rtdm_copy_from_user(user_info,
					    &fromto,
					    arg,
					    sizeof(fromto));

			return rtswitch_to_rt(ctx, fromto.from, fromto.to);

		default:
			return -ENOTTY;
		}
}

static struct rtdm_device device = {
	struct_version: RTDM_DEVICE_STRUCT_VER,

	device_flags: RTDM_NAMED_DEVICE,
	context_size: sizeof(rtswitch_context_t),
	device_name:  "",

	open_rt: NULL,
	open_nrt: rtswitch_open,

	ops: {
		close_rt: NULL,
		close_nrt: rtswitch_close,

		ioctl_rt: rtswitch_ioctl_rt,
		ioctl_nrt: rtswitch_ioctl_nrt,

		read_rt: NULL,
		read_nrt: NULL,

		write_rt: NULL,
		write_nrt: NULL,

		recvmsg_rt: NULL,
		recvmsg_nrt: NULL,

		sendmsg_rt: NULL,
		sendmsg_nrt: NULL,
	},

	device_class: RTDM_CLASS_TESTING,
	device_sub_class: RTDM_SUBCLASS_SWITCHTEST,
	profile_version: RTTST_PROFILE_VER,
	driver_name: "xeno_switchtest",
	driver_version: RTDM_DRIVER_VER(0, 1, 1),
	peripheral_name: "Context Switch Test",
	provider_name: "Gilles Chanteperdrix",
	proc_name: device.device_name,
};

void rtswitch_utask_waker(rtdm_nrtsig_t sig, void *arg)
{
	up(&rtswitch_utask[xnarch_current_cpu()]->nrt_synch);
}

int __init __switchtest_init(void)
{
	int err;

	err = rtdm_nrtsig_init(&rtswitch_wake_utask,
			       rtswitch_utask_waker, NULL);
	if (err)
		return err;

	do {
		snprintf(device.device_name, RTDM_MAX_DEVNAME_LEN, "rttest%d",
			 start_index);
		err = rtdm_dev_register(&device);

		start_index++;
	} while (err == -EEXIST);

	return err;
}

void __switchtest_exit(void)
{
	rtdm_dev_unregister(&device, 1000);
	rtdm_nrtsig_destroy(&rtswitch_wake_utask);
}

module_init(__switchtest_init);
module_exit(__switchtest_exit);
