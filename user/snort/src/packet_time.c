/**
 * @file   packet_time.c
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Tue Jun 17 17:09:59 2003
 * 
 * @brief  Easily allow modules to have a gettimeofday() based on packet time
 * 
 * In many modules in snort, especially the rate detectors need to
 * work based off time values.  It's very hard to reproduce time
 * constraints via pcap readbacks so we either have to throttle snort
 * or use the packet time.  I choose the latter.
 */

#include "packet_time.h"

static time_t s_first_packet  = 0;
static time_t s_recent_packet = 0;

void packet_time_update(time_t cur)
{
    if(s_first_packet == 0)
    {
        s_first_packet = cur;
    }

    s_recent_packet = cur;
}

time_t packet_timeofday(void)
{
    return s_recent_packet;
}

time_t packet_first_time(void)
{
    return s_first_packet;
}
