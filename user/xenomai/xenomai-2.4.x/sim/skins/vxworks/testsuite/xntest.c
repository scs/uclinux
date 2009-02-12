/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>.
 * Copyright (C) 2001,2002 IDEALX (http://www.idealx.com/).
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include <nucleus/xenomai.h>
#include "xntest.h"
#include <stdarg.h>

typedef struct xntest_mark
{
    char *threadname;
    int count;
    xnholder_t link;

#define link2mark(laddr)                                                        \
((xntest_mark_t *)(((char *)laddr) - (int)(&((xntest_mark_t *)0)->link)))

} xntest_mark_t;


typedef void (*xntimer_handler) (void *);



static xnqueue_t marks_q;
static xnlock_t test_lock = XNARCH_LOCK_UNLOCKED;
static xntimer_t watchdog;
static int test_failures;
static int tests;

int xntest_verbose = 0;

module_param_named(xntest_verbose, xntest_verbose, int, 0444);
MODULE_PARM_DESC(xntest_verbose, "Set to 1 to make test verbose");

static inline xnholder_t *gettailq (xnqueue_t *qslot) {
    xnholder_t *holder = qslot->head.last;
    if (holder == &qslot->head) return NULL;
    return holder;
}

/* 30 seconds */
#define test_timeout 30

static inline int strings_differ(const char *str1, const char *str2)
{
    return ((!str1 || !str2) ? str1!=str2 : strcmp(str1, str2));
}

static void interrupt_test (xntimer_t *dummy)
{
   xnpod_fatal("\ntest interrupted by watchdog.\n");
}



void xntest_start(void)
{
    spl_t s;

    if (module_param_value(xntest_verbose) >= 0)
        xntest_verbose = module_param_value(xntest_verbose);

    xnlock_get_irqsave(&test_lock, s);
    xntimer_init(&watchdog, &nktbase, interrupt_test);
    xntimer_start(&watchdog, xntbase_ns2ticks(&nktbase, test_timeout * 1000000000ULL), XN_INFINITE, XN_RELATIVE);

    initq(&marks_q);
    tests=0;
    test_failures=0;
    xnlock_put_irqrestore(&test_lock, s);
}



int xntest_assert(int status, char *assertion, char *file, int line)
{
    spl_t s;

    xnlock_get_irqsave(&test_lock, s);
    ++tests;
    if(!status) {
        ++test_failures;
        xnarch_printf("%s:%d: TEST failed: %s\n", file, line, assertion);
    } else if (xntest_verbose)
        xnarch_printf("%s:%d TEST passed.\n", file, line);
    xnlock_put_irqrestore(&test_lock, s);

    return status;
}

void xntest_mark(xnthread_t *thread)
{
    xnholder_t *holder;
    xntest_mark_t *mark;
    const char *threadname;
    spl_t s;

    xnlock_get_irqsave(&test_lock, s);
    holder = gettailq(&marks_q);
    threadname = xnthread_name(thread);

    if(!holder ||
       strings_differ(threadname, (mark=link2mark(holder))->threadname)) {
        size_t namelen = threadname ? strlen(threadname)+1: 0;
        mark = (xntest_mark_t *) xnmalloc(sizeof(xntest_mark_t)+namelen);
        mark->threadname=(threadname
                          ? (char *) mark + sizeof(xntest_mark_t)
                          : NULL);
        if(mark->threadname)
            memcpy(mark->threadname, threadname, namelen);
        
        mark->count = 1;
        inith(&mark->link);
        appendq(&marks_q, &mark->link);
    } else
        mark->count++;
    xnlock_put_irqrestore(&test_lock, s);
}



void xntest_check_seq(int next, ...)
{
    xntest_mark_t *mark;
    xnholder_t *holder;
    char *file, *name;
    int line, count;
    va_list args;
    spl_t s;

    va_start(args, next);

    xnlock_get_irqsave(&test_lock, s);
    holder = getheadq(&marks_q);

    while(next) {
        file = va_arg(args,char *);
        line = va_arg(args,int);
        name = va_arg(args,char *);
        count = va_arg(args,int);
        ++tests;
        if(holder == NULL) {
            xnarch_printf("%s:%d: Expected sequence: SEQ(\"%s\",%d); "
                          "reached end of recorded sequence.\n",
                          file, line, name, count);
            ++test_failures;
        } else {
            mark = link2mark(holder);

            if(strings_differ(mark->threadname, name) || mark->count != count ) {
                xnarch_printf("%s:%d: Expected sequence: SEQ(\"%s\",%d); "
                              "got SEQ(\"%s\",%d)\n",
                              file,
                              line,
                              name,
                              count,
                              mark->threadname,
                              mark->count);
                ++test_failures;
            } else
                xnarch_printf("%s:%d Correct sequence: SEQ(\"%s\",%d)\n",
                              file, line, name, count);

            holder = nextq(&marks_q, holder);
        }
        next = va_arg(args, int);
    }
    xnlock_put_irqrestore(&test_lock, s);
    va_end(args);
}



void xntest_finish(char *file, int line)
{
    xnholder_t *next_holder;
    xnholder_t *holder;
    spl_t s;
    
    xntimer_destroy(&watchdog);

    xnlock_get_irqsave(&test_lock, s);
    for(holder = getheadq(&marks_q); holder ; holder=next_holder)
    {
        next_holder = nextq(&marks_q, holder);
        removeq(&marks_q, holder);
        xnfree(link2mark(holder));
    }
    xnlock_put_irqrestore(&test_lock, s);

    xnarch_printf("%s:%d, test finished: %d failures/ %d tests\n",
                  file, line, test_failures, tests);
    xnpod_fatal("Normal exit.\n");
}
