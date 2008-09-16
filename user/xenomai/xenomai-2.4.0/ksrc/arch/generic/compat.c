#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/workqueue.h>	/* compat/include/linux/ */
#include <asm/semaphore.h>

struct kthread_arg_block {
    int (*threadfn)(void *data);
    void *data;
    struct completion started;
};

struct kthread_stop_block {
    struct task_struct *p;
    struct completion done;
    int ret;
};

static DECLARE_MUTEX(kthread_stop_sem);

static struct kthread_stop_block kthread_stop_info;

int kthread_should_stop(void)
{
    return kthread_stop_info.p == current;
}

static void kthread_trampoline(void *data)
{
    struct kthread_arg_block *bp = data;
    int (*threadfn)(void *data);
    sigset_t blocked;
    int ret = -EINTR;
    void *tdata;

    daemonize();

    sigfillset(&blocked);
    threadfn = bp->threadfn;
    tdata = bp->data;

    __set_current_state(TASK_INTERRUPTIBLE);
    complete(&bp->started);
    schedule();

    if (!kthread_should_stop())
	ret = threadfn(tdata);

    if (kthread_should_stop())
	{
	kthread_stop_info.ret = ret;
	complete(&kthread_stop_info.done);
	}
}

struct task_struct *kthread_create(int (*threadfn)(void *data),
				   void *data,
				   const char namefmt[],
				   ...)
{
    struct kthread_arg_block b;
    struct task_struct *p;
    va_list ap;
    int pid;

    b.threadfn = threadfn;
    b.data = data;
    init_completion(&b.started);

    pid = kernel_thread((void *)&kthread_trampoline,&b,0);

    if (pid < 0)
	return NULL;

    wait_for_completion(&b.started);
    p = find_task_by_pid(pid);
    va_start(ap,namefmt);
    vsnprintf(p->comm,sizeof(p->comm),namefmt,ap);
    va_end(ap);

    return p;
}

int kthread_stop(struct task_struct *p)
{
    int ret;

    down(&kthread_stop_sem);

    init_completion(&kthread_stop_info.done);
    smp_wmb();
    kthread_stop_info.p = p;
    wake_up_process(p);

    wait_for_completion(&kthread_stop_info.done);
    kthread_stop_info.p = NULL;
    ret = kthread_stop_info.ret;

    up(&kthread_stop_sem);

    return ret;
}

EXPORT_SYMBOL(kthread_create);
EXPORT_SYMBOL(kthread_should_stop);
EXPORT_SYMBOL(kthread_stop);
