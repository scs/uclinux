#include <asm/xenomai/wrappers.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/workqueue.h>	/* compat/include/linux/ */
#include <linux/bitops.h>
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

static inline unsigned long __ffs_compat(unsigned long word)
{
	if ((unsigned)(word))
		return ffs(word) - 1;
#if BITS_PER_LONG == 64
	if (word >> 32)
		return 31 + ffs(word >> 32);
	return 64;
#else
	return 32;
#endif /* 64 bits */
}

unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
			    unsigned long offset)
{
        const unsigned long *p = addr + BITOP_WORD(offset);
        unsigned long result = offset & ~(BITS_PER_LONG-1);
        unsigned long tmp;

        if (offset >= size)
                return size;
        size -= result;
        offset %= BITS_PER_LONG;
        if (offset) {
                tmp = *(p++);
                tmp &= (~0UL << offset);
                if (size < BITS_PER_LONG)
                        goto found_first;
                if (tmp)
                        goto found_middle;
                size -= BITS_PER_LONG;
                result += BITS_PER_LONG;
        }
        while (size & ~(BITS_PER_LONG-1)) {
                if ((tmp = *(p++)))
                        goto found_middle;
                result += BITS_PER_LONG;
                size -= BITS_PER_LONG;
        }
        if (!size)
                return result;
        tmp = *p;

found_first:
        tmp &= (~0UL >> (BITS_PER_LONG - size));
        if (tmp == 0UL)         /* Are any bits set? */
                return result + size;   /* Nope. */
found_middle:
        return result + __ffs_compat(tmp);
}
