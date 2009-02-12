#ifndef __XENO_SIM__
#ifndef __KERNEL__
#include <stdio.h>
#define xnarch_printf printf
#endif

#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <pthread.h>
#include <mqueue.h>
#else /* __XENO_SIM */
#include <posix/posix.h>
#endif /* __XENO_SIM */

#define CONSUMER_TASK_PRI    1
#define CONSUMER_STACK_SIZE  8192

#define PRODUCER_TASK_PRI    2
#define PRODUCER_STACK_SIZE  8192

#define CONSUMER_WAIT 150
#define PRODUCER_TRIG 40

#define MQ_NAME "/satchmq"
#define SHM_NAME "/satchshm"

void normalize(struct timespec *ts)
{
    if (ts->tv_nsec > 1000000000)
        {
        ts->tv_sec += ts->tv_nsec / 1000000000;
        ts->tv_nsec %= 1000000000;
        }

    if (ts->tv_nsec < 0)
        {
        ts->tv_sec -= (-ts->tv_nsec) / 1000000000 + 1;
        ts->tv_nsec = 1000000000 - (-ts->tv_nsec % 1000000000);
        }
}

void abort_perror(const char *pref)
{
    xnprintf("%s: %d\n", pref, errno);
    pthread_exit(NULL);
}

#ifdef PRODUCER

static const char *private_satch_s_tunes[] = {
    "Surfing With The Alien",
    "Lords of Karma",
    "Banana Mango",
    "Psycho Monkey",
    "Luminous Flesh Giants",
    "Moroccan Sunset",
    "Satch Boogie",
    "Flying In A Blue Dream",
    "Ride",
    "Summer Song",
    "Speed Of Light",
    "Crystal Planet",
    "Raspberry Jam Delta-V",
    "Champagne?",
    "Clouds Race Across The Sky",
    "Engines Of Creation"
};

static unsigned satch_s_tunes[sizeof(private_satch_s_tunes)/sizeof(char *)];
static timer_t producer_tm = (timer_t) -1;
static mqd_t producer_mq = (mqd_t) -1;
static void *producer_shm = MAP_FAILED;
static pthread_t producer_task;

void *producer (void *cookie)

{
    struct itimerspec its;
    sigset_t blocked;
    unsigned pos;
    int next_msg;

    /* Copy the strings to shared memory. */
    pos = 0;
    for (next_msg = 0;
         next_msg < sizeof(private_satch_s_tunes)/sizeof(char *);
         next_msg++)
        {
        const char *msg = private_satch_s_tunes[next_msg];
        size_t len = strlen(msg) + 1;
        memcpy(producer_shm + pos, msg, len);
        satch_s_tunes[next_msg] = pos;
        pos += len;
        }
    next_msg = 0;

    sigemptyset(&blocked);
    sigaddset(&blocked, SIGRTMIN+1);
    pthread_sigmask(SIG_BLOCK, &blocked, NULL);

    its.it_value.tv_sec = 0;
    its.it_value.tv_nsec = 10000000 * PRODUCER_TRIG;
    normalize(&its.it_value);
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;
    normalize(&its.it_interval);

    for (;;)
	{
        unsigned msg_off;
        siginfo_t si;
        int nchar;

        if (timer_settime(producer_tm, 0, &its, NULL))
            abort_perror("timer_settime");
        while (sigwaitinfo(&blocked, &si) == -1 && errno == EINTR)
            ;

	msg_off = satch_s_tunes[next_msg++];
	next_msg %= (sizeof(satch_s_tunes) / sizeof(satch_s_tunes[0]));

        do 
            {
            nchar = mq_send(producer_mq, (char *)&msg_off, sizeof(msg_off), 0);
            }
        while (nchar == -1 && errno == EINTR);

        if (nchar == -1)
            abort_perror("mq_send");
	}

    return NULL;
}

#endif /* PRODUCER */

#ifdef CONSUMER

static timer_t consumer_tm = (timer_t) -1;
static mqd_t consumer_mq = (mqd_t) -1;
static void *consumer_shm = MAP_FAILED;
static pthread_t consumer_task;

void *consumer (void *cookie)

{
    struct itimerspec its;
    sigset_t blocked;
    
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &blocked, NULL);

    its.it_value.tv_sec = 0;
    its.it_value.tv_nsec = CONSUMER_WAIT * 10000000; /* 10 ms */
    normalize(&its.it_value);
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = CONSUMER_WAIT * 10000000;
    normalize(&its.it_interval);

    if(timer_settime(consumer_tm, 0, &its, NULL))
        abort_perror("timer_settime");

    for (;;)
	{
        siginfo_t si;
        while (sigwaitinfo(&blocked, &si) == -1 && errno == EINTR)
            ;

        for (;;)
	    {
            unsigned prio;
            unsigned msg;
            int nchar;

            do 
                {
                nchar = mq_receive(consumer_mq,(char *)&msg, sizeof(msg), &prio);
                }
            while (nchar == -1 && errno == EINTR);
            
            if (nchar == -1 && errno == EAGAIN)
                break;

            if (nchar == -1)
                abort_perror("mq_receive");

	    printf("Now playing %s...\n",(char *) consumer_shm + msg);
	    }
	}

    return NULL;
}

#endif /* CONSUMER */

void __xeno_user_exit (void)

{
#ifdef PRODUCER
    if (producer_task)
        {
        pthread_cancel(producer_task);
        pthread_join(producer_task, NULL);
        }
    if (producer_tm != (timer_t) -1)
        timer_delete(producer_tm);
    if (producer_mq != (mqd_t) -1)
        mq_close(producer_mq);
    mq_unlink(MQ_NAME);
    if (producer_shm != MAP_FAILED)
        munmap(producer_shm, 65536);
    shm_unlink(SHM_NAME);
#endif /* PRODUCER */

#ifdef CONSUMER
    if (consumer_task)
        {
        pthread_cancel(consumer_task);
        pthread_join(consumer_task, NULL);
        }
    if (consumer_tm != (timer_t) -1)
        timer_delete(consumer_tm);
    if (consumer_mq != (mqd_t) -1)
        mq_close(consumer_mq);
    if (consumer_shm != MAP_FAILED)
        munmap(consumer_shm, 65536);
#endif /* CONSUMER */
}

int __xeno_user_init (void)

{
    struct sched_param parm;
    pthread_attr_t attr;
    int rc = 0, fd = -1;
    struct mq_attr mattr;
    struct sigevent evt;

    fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0777);
    if (fd == -1)
        {
        xnprintf("shm_open: %d\n", errno);
        return -errno;
        }

    if (ftruncate(fd, 65536))
        {
        xnprintf("ftruncate: %d\n", errno);
        goto out;
        }

    pthread_attr_init(&attr);
    pthread_attr_setinheritsched(&attr, 1);
    pthread_attr_setschedpolicy(&attr, SCHED_FIFO);

#ifdef PRODUCER
    mattr.mq_maxmsg = 30;
    mattr.mq_msgsize = sizeof(unsigned);
    producer_mq = mq_open(MQ_NAME, O_CREAT| O_EXCL| O_WRONLY, 0, &mattr);
    if (producer_mq == (mqd_t) -1)
        {
	if (errno == EEXIST)
	    {
	    xnprintf("Satch: producer module is already running, please "
		     "only launch one producer instance.\n");
	    goto out;
	    }

        xnprintf("mq_open(producer_mq): %d\n", errno);
        goto out;
        }
    
    producer_shm = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (producer_shm == MAP_FAILED)
        {
        xnprintf("mmap(producer_shm): %d\n", errno);
        return -errno;
        }

    evt.sigev_notify = SIGEV_SIGNAL;
    evt.sigev_signo = SIGRTMIN+1;
    evt.sigev_value.sival_ptr = &producer_tm;
    if (timer_create(CLOCK_REALTIME, &evt, &producer_tm))
        {
        xnprintf("timer_create(producer_tm): %d\n", errno);
        goto out;
        }

    pthread_attr_setstacksize(&attr, PRODUCER_STACK_SIZE);
    parm.sched_priority = PRODUCER_TASK_PRI;
    pthread_attr_setschedparam(&attr, &parm);
    rc = pthread_create(&producer_task, &attr, &producer, NULL);

    if (rc)
        {
        xnprintf("pthread_create(producer_task): %d\n", rc);
        goto out;
        }
#endif /* PRODUCER */

#ifdef CONSUMER
    mattr.mq_maxmsg = 30;
    mattr.mq_msgsize = sizeof(unsigned);
    consumer_mq = mq_open(MQ_NAME, O_NONBLOCK| O_RDONLY, 0, &mattr);
    if (consumer_mq == (mqd_t) -1)
        {
	if (errno == ENOENT)
	    {
	    xnprintf("Satch: producer module not running, please launch producer"
		     " module before\nlaunching consumer application.\n");
	    goto out;
	    }

        xnprintf("mq_open(consumer_mq): %d\n", errno);
        goto out;
        }

    consumer_shm = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (consumer_shm == MAP_FAILED)
        {
        xnprintf("mmap(consumer_shm): %d\n", errno);
        goto out;
        }

    evt.sigev_notify = SIGEV_SIGNAL;
    evt.sigev_signo = SIGALRM;
    evt.sigev_value.sival_ptr = &consumer_tm;
    if(timer_create(CLOCK_REALTIME, &evt, &consumer_tm))
        {
        xnprintf("timer_create(consumer_tm): %d\n", errno);
        goto out;
        }

    pthread_attr_setstacksize(&attr, CONSUMER_STACK_SIZE);
    parm.sched_priority = CONSUMER_TASK_PRI;
    pthread_attr_setschedparam(&attr, &parm);
    rc = pthread_create(&consumer_task, &attr, &consumer, NULL);
    if (rc)
        {
        xnprintf("pthread_create(consumer_task): %d\n", rc);
        goto out;
        }
#endif /* CONSUMER */

    if (close(fd))
        {
        xnprintf("close: %d\n", errno);
        rc = -errno;
	goto err;
        }

    return 0;

  out:
    rc = -rc ?: -errno;
    if (close(fd))
	    
        xnprintf("close: %d\n", errno);
  err:
    __xeno_user_exit();
    return rc;
}

#ifdef __KERNEL__
MODULE_AUTHOR("gilles.chanteperdrix@laposte.net");
MODULE_LICENSE("GPL");
module_init(__xeno_user_init);
module_exit(__xeno_user_exit);

#elif !defined(__XENO_SIM__)
int main (int ac, char *av[])

{
    sigset_t mask;
    int rc, sig;

    sigemptyset(&mask);
    sigaddset(&mask,SIGINT);
    sigaddset(&mask,SIGTERM);
    sigaddset(&mask,SIGHUP);
    sigaddset(&mask,SIGALRM);

    pthread_sigmask(SIG_BLOCK, &mask, NULL);

    mlockall(MCL_CURRENT|MCL_FUTURE);

    rc = __xeno_user_init();

    if (rc)
        {
        xnprintf("__xeno_user_init: %d\n", -rc);
        return -rc;
        }

    sigwait(&mask, &sig);
    __xeno_user_exit();

    return 0;
}
#endif /* !__XENO_SIM__ && !__KERNEL__ */
