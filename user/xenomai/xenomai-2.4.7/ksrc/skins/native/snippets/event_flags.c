#include <native/event.h>

#define EVENT_INIT        0x0           /* No flags present at init */
#define EVENT_MODE        EV_PRIO       /* Tasks will wait by priority order */
#define EVENT_WAIT_MASK   (0x1|0x2|0x4) /* List of monitored events */
#define EVENT_SIGNAL_MASK (0x2)	        /* List of events to send */

RT_EVENT ev_desc;

void foo (void)

{
    unsigned long mask_ret;
    int err;

    /* Create an event flag; we could also have attempted to bind to
       some pre-existing object, using rt_event_bind() instead of
       creating it. */

    err = rt_event_create(&ev_desc,
			  "MyEventFlagGroup",
			  EVENT_INIT,
			  EVENT_MODE);

    /* Now, wait for some task to post some event flags... */

    err = rt_event_wait(&ev_desc,
			EVENT_WAIT_MASK,
			&mask_ret,
			EV_ANY,	/* Disjunctive wait */
			TM_INFINITE);
    /* ... */
}

void bar (void)

{
    /* ... */

    /* Post some events. */

    rt_event_signal(&ev_desc,EVENT_SIGNAL_MASK);

    /* ... */
}

void cleanup (void)

{
    rt_event_delete(&ev_desc);
}
