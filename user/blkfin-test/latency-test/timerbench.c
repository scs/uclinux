/*
 * Copyright (C) 2005 Jan Kiszka <jan.kiszka@web.de>.
 * 
 * Modified by Yi Li (yi.li@analog.com) for non-rt Linux  
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/interrupt.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/blackfin.h>
#include <asm/semaphore.h>
#include <asm/uaccess.h>
#include <asm/div64.h>

#include "timerbench.h"

static void tb_timer_start (long period_tsc);
static void tb_timer_stop (void);
static int tb_timer_init (int (*f) (int, void *, struct pt_regs *), void *);

struct rt_tmbench_context
{
  int mode;
  unsigned long period;
  int freeze_max;
  int warmup_loops;
  int samples_per_sec;
  long *histogram_min;
  long *histogram_max;
  long *histogram_avg;
  int histogram_size;
  int bucketsize;

  int warmup;
  volatile unsigned long long start_time;
  unsigned long long date;
  struct rttst_bench_res curr;

  wait_queue_head_t *result_event;
  struct rttst_interm_bench_res result;

  struct semaphore nrt_mutex;
  int done;
} tb_ctx;

static long tb_cclk;
static long tb_sclk;


#define read_tsc(t)					\
	({							\
	volatile unsigned long __cy2;					\
	__asm__ __volatile__ (	"1: %0 = CYCLES2\n"		\
				"%1 = CYCLES\n"			\
				"%2 = CYCLES2\n"		\
				"CC = %2 == %0\n"		\
				"if ! CC jump 1b\n"		\
				:"=r" (((unsigned long *)&t)[1]),	\
				"=r" (((unsigned long *)&t)[0]),	\
				"=r" (__cy2)				\
				: /*no input*/ : "CC");			\
	t;								\
	})

static DECLARE_WAIT_QUEUE_HEAD (tb_wq);

MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("yi.li@analog.com");

static inline long
ns2tsc (long ns)
{
  return ((ns / 1000) * (tb_cclk / 1000000));
}

static inline long
tsc2ns (long tsc)
{
  return ((tsc) / (tb_cclk / 1000000) * 1000);
}

static inline void
add_histogram (struct rt_tmbench_context *ctx, long *histogram, long addval)
{
  /* bucketsize steps */
  long inabs = (addval >= 0 ? addval : -addval) / ctx->bucketsize;
  histogram[inabs < ctx->histogram_size ? inabs : ctx->histogram_size - 1]++;
}

/* Kernel do not use udivd3() functions defined in libgcc */
static inline unsigned long long
ulldiv (unsigned long long ull, const unsigned uld, unsigned long *const rp)
{
  const unsigned r = do_div (ull, uld);
  if (rp)
    *rp = r;
  return ull;
}

static inline long long
slldiv (long long s, unsigned d)
{
  return s >= 0 ? ulldiv (s, d, NULL) : -ulldiv (-s, d, NULL);
}

void
eval_inner_loop (struct rt_tmbench_context *ctx, long dt)
{
  if (ctx->date <= ctx->start_time)
    ctx->curr.overruns++;

  if (dt > ctx->curr.max)
    ctx->curr.max = dt;
  if (dt < ctx->curr.min)
    ctx->curr.min = dt;
  ctx->curr.avg += dt;

  ctx->date += ctx->period;

  if (!ctx->warmup && ctx->histogram_size)
    add_histogram (ctx, ctx->histogram_avg, tsc2ns (dt));

  /* Evaluate overruns and adjust next release date.
   * Beware of signedness! */
  while (dt > 0 && (unsigned long) dt > ctx->period)
    {
      ctx->curr.overruns++;
      ctx->date += ctx->period;
      dt -= ctx->period;
    }
}


void
eval_outer_loop (struct rt_tmbench_context *ctx)
{
  long curr_max_ns = tsc2ns (ctx->curr.max);
  long curr_min_ns = tsc2ns (ctx->curr.min);
  long curr_avg_ns = tsc2ns (ctx->curr.avg);

  if (!ctx->warmup)
    {
      if (ctx->histogram_size)
	{
	  add_histogram (ctx, ctx->histogram_max, curr_max_ns);
	  add_histogram (ctx, ctx->histogram_min, curr_min_ns);
	}

      ctx->result.last.min = curr_min_ns;
      if (curr_min_ns < ctx->result.overall.min)
	ctx->result.overall.min = curr_min_ns;

      ctx->result.last.max = curr_max_ns;
      if (curr_max_ns > ctx->result.overall.max)
	ctx->result.overall.max = curr_max_ns;

      ctx->result.last.avg = slldiv (curr_avg_ns, ctx->samples_per_sec);
      ctx->result.overall.avg += ctx->result.last.avg;
      ctx->result.overall.overruns += ctx->curr.overruns;
      wake_up_interruptible (ctx->result_event);
    }

  if (ctx->warmup && (ctx->result.overall.test_loops == ctx->warmup_loops))
    {
      ctx->result.overall.test_loops = 0;
      ctx->warmup = 0;
    }

  ctx->curr.min = 10000000;
  ctx->curr.max = -10000000;
  ctx->curr.avg = 0;
  ctx->curr.overruns = 0;

  ctx->result.overall.test_loops++;
  ctx->done = 1;
}

static irqreturn_t
timer_proc (int irq, void *dev_id, struct pt_regs *regs)
{
  struct rt_tmbench_context *ctx = (struct rt_tmbench_context *) dev_id;
  volatile unsigned long long tsc;

  read_tsc (tsc);
  eval_inner_loop (ctx, (long) (tsc - ctx->date));

  tb_timer_stop ();

  read_tsc (ctx->start_time);

  tb_timer_start ((long) (ctx->date - ctx->start_time));

  if (++ctx->curr.test_loops < ctx->samples_per_sec)
    return IRQ_HANDLED;

  ctx->curr.test_loops = 0;
  eval_outer_loop (ctx);

  return IRQ_HANDLED;
}

static irqreturn_t
user_timer_proc (int irq, void *dev_id, struct pt_regs *regs)
{
  struct rt_tmbench_context *ctx = (struct rt_tmbench_context *) dev_id;

  tb_timer_stop ();
  wake_up_interruptible (ctx->result_event);
  ctx->done = 1;
  return IRQ_HANDLED;
}


int
tb_open (struct inode *inode, struct file *filp)
{
  struct rt_tmbench_context *ctx = &tb_ctx;

  memset (&tb_ctx, 0, sizeof (tb_ctx));
  filp->private_data = ctx;
  ctx->done = 0;
  ctx->mode = -1;
  ctx->result_event = &tb_wq;

  init_MUTEX (&ctx->nrt_mutex);

  return 0;
}

int
tb_timer_init (int (*handler) (int, void *, struct pt_regs *), void *arg)
{
  int ret = 0;
  ret = request_irq (IRQ_WATCH, handler, IRQF_DISABLED, "Timerbench", arg);
  if (ret < 0)
    printk (KERN_ERR "request_irq() error\n");
  return ret;
}

void
tb_timer_start (long period_tsc)
{
  if (period_tsc < 0)
    period_tsc = 0;

  bfin_write_WDOG_CNT (period_tsc / (tb_cclk / tb_sclk));
  bfin_write_WDOG_CTL (0x0004);
}

void
tb_timer_stop ()
{
  bfin_write_WDOG_CTL (0x8AD6);
  bfin_write_WDOG_CTL (0x8AD6);
}

int
tb_release (struct inode *inode, struct file *filp)
{
  struct rt_tmbench_context *ctx;

  ctx = (struct rt_tmbench_context *) filp->private_data;

  down (&ctx->nrt_mutex);

  if (ctx->mode >= 0)
    {
      tb_timer_stop ();

      if (ctx->histogram_size)
	kfree (ctx->histogram_min);

      ctx->mode = -1;
      ctx->histogram_size = 0;
    }

  up (&ctx->nrt_mutex);

  return 0;
}

int
tb_ioctl (struct inode *inode, struct file *filp, uint cmd, unsigned long arg)
{
  struct rt_tmbench_context *ctx;
  int ret = 0;
  volatile unsigned long long tsc = 0;

  ctx = (struct rt_tmbench_context *) filp->private_data;

  switch (cmd)
    {
    case RTTST_RTIOC_TMBENCH_START:
      {
	struct rttst_tmbench_config config_buf;
	struct rttst_tmbench_config *config;

	copy_from_user (&config_buf, (void *) arg,
			sizeof (struct rttst_tmbench_config));
	config = &config_buf;

	down (&ctx->nrt_mutex);

	ctx->period = ns2tsc (config->period);
	ctx->warmup_loops = config->warmup_loops;
	ctx->samples_per_sec = 1000000000 / (long) config->period;
	ctx->histogram_size = config->histogram_size;
	ctx->freeze_max = config->freeze_max;

	if (ctx->histogram_size > 0)
	  {
	    ctx->histogram_min =
	      kmalloc (3 * ctx->histogram_size * sizeof (long), GFP_KERNEL);
	    ctx->histogram_max = ctx->histogram_min + config->histogram_size;
	    ctx->histogram_avg = ctx->histogram_max + config->histogram_size;

	    if (!ctx->histogram_min)
	      {
		up (&ctx->nrt_mutex);
		return -ENOMEM;
	      }

	    memset (ctx->histogram_min, 0,
		    3 * ctx->histogram_size * sizeof (long));
	    ctx->bucketsize = config->histogram_bucketsize;
	  }

	ctx->result.overall.min = 10000000;
	ctx->result.overall.max = -10000000;
	ctx->result.overall.avg = 0;
	ctx->result.overall.test_loops = 1;
	ctx->result.overall.overruns = 0;

	ctx->warmup = 1;

	ctx->curr.min = 10000000;
	ctx->curr.max = -10000000;
	ctx->curr.avg = 0;
	ctx->curr.overruns = 0;

	//ctx->result_event = &tb_wq;

	ctx->curr.test_loops = 0;

	ctx->mode = RTTST_TMBENCH_HANDLER;
	read_tsc (tsc);
	ctx->start_time = tsc + 1000000;
	ctx->date = ctx->start_time + ctx->period;

	tb_timer_init (timer_proc, &tb_ctx);

	read_tsc (tsc);
	tb_timer_start ((long) (ctx->date - tsc));

	up (&ctx->nrt_mutex);

	break;
      }

    case RTTST_RTIOC_TMBENCH_STOP:
      {
	struct rttst_overall_bench_res *usr_res;

	usr_res = (struct rttst_overall_bench_res *) arg;

	down (&ctx->nrt_mutex);

	if (ctx->mode < 0)
	  {
	    up (&ctx->nrt_mutex);
	    return -EINVAL;
	  }

	tb_timer_stop ();

	ctx->mode = -1;

	ctx->result.overall.avg =
	  slldiv (ctx->result.overall.avg,
		  (((ctx->result.overall.test_loops) > 1 ?
		    ctx->result.overall.test_loops : 2) - 1));

	copy_to_user (&usr_res->result,
		      &ctx->result.overall, sizeof (struct rttst_bench_res));

	if (ctx->histogram_size)
	  {
	    int size = ctx->histogram_size * sizeof (long);

	    copy_to_user (usr_res->histogram_min, ctx->histogram_min, size);
	    copy_to_user (usr_res->histogram_max, ctx->histogram_max, size);
	    copy_to_user (usr_res->histogram_avg, ctx->histogram_avg, size);
	    kfree (ctx->histogram_min);
	  }

	up (&ctx->nrt_mutex);

	free_irq (IRQ_WATCH, &tb_ctx);

	break;
      }

    case RTTST_RTIOC_INTERM_BENCH_RES:
      {
	struct rttst_interm_bench_res *usr_res;

	usr_res = (struct rttst_interm_bench_res *) arg;

	ret = wait_event_interruptible (*(ctx->result_event), ctx->done != 0);
	if (ret < 0)
	  return ret;

	ctx->done = 0;

	copy_to_user (usr_res, &ctx->result,
		      sizeof (struct rttst_interm_bench_res));

	break;
      }

    case RTTST_GETCCLK:
      {
	copy_to_user ((void *) arg, &tb_cclk, sizeof (tb_cclk));
	break;
      }

    case RTTST_TMR_START:
      {
	struct timer_info t_info;

	copy_from_user (&t_info, (void *) arg, sizeof (t_info));
	ctx->period = t_info.period_tsc;
	ctx->start_time = t_info.start_tsc;
	ctx->date = ctx->start_time + ctx->period;

	tb_timer_init (user_timer_proc, &tb_ctx);

	read_tsc (tsc);
	tb_timer_start ((long) (ctx->date - tsc));
	break;
      }

    case RTTST_TMR_WAIT:
      {
	ctx->curr.overruns = 0;

	ret = wait_event_interruptible (*(ctx->result_event), ctx->done != 0);
	if (ret < 0)
	  return ret;

	ctx->date += ctx->period;
	read_tsc (ctx->start_time);

	//printk("KERNEL: wake up - tsc: %lld, overrun: %ld\n", 
	//ctx->start_time, ctx->curr.overruns);    

	if (ctx->date <= ctx->start_time)
	  {
	    while (ctx->date <= ctx->start_time)
	      {
		/* set next release point */
		ctx->curr.overruns++;
		ctx->date += ctx->period;
	      }
	    ret = -ETIMEDOUT;
	  }
	ctx->done = 0;
	tb_timer_start ((long) (ctx->date - ctx->start_time));
	copy_to_user ((void *) arg, &(ctx->curr.overruns),
		      sizeof (ctx->curr.overruns));
	break;
      }

    case RTTST_TMR_STOP:
      {
	tb_timer_stop ();
	free_irq (IRQ_WATCH, &tb_ctx);
	break;
      }

    default:
      printk ("%s: bad ioctl code (0x%x)\n", __FUNCTION__, cmd);
      ret = -ENOTTY;
    }

  return ret;
}

static struct file_operations tb_fops = {
  .owner = THIS_MODULE,
  .ioctl = tb_ioctl,
  .open = tb_open,
  .release = tb_release,
};


int __init
__timerbench_init (void)
{
  int ret = 0;

  ret = register_chrdev (TB_MAJOR, TB_DEVNAME, &tb_fops);

  tb_cclk = get_cclk ();
  tb_sclk = get_sclk ();

  return ret;
}


void
__timerbench_exit (void)
{
  unregister_chrdev (TB_MAJOR, TB_DEVNAME);
}


module_init (__timerbench_init);
module_exit (__timerbench_exit);
