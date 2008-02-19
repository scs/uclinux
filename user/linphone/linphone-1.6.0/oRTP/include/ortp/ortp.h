/*
  The oRTP library is an RTP (Realtime Transport Protocol - rfc3550) stack.
  Copyright (C) 2001  Simon MORLAT simon.morlat@linphone.org

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/


#ifndef ORTP_H
#define ORTP_H

#include <ortp/rtpsession.h>
#include <ortp/sessionset.h>

#ifdef __cplusplus
extern "C"
{
#endif

bool_t ortp_min_version_required(int major, int minor, int micro);
void ortp_init(void);
void ortp_scheduler_init(void);
void ortp_exit(void);

/***************/
/* logging api */
/***************/

typedef enum {
	ORTP_DEBUG=1,
	ORTP_MESSAGE=1<<1,
	ORTP_WARNING=1<<2,
	ORTP_ERROR=1<<3,
	ORTP_FATAL=1<<4,
	ORTP_LOGLEV_END=1<<5
} OrtpLogLevel;


typedef void (*OrtpLogFunc)(OrtpLogLevel lev, const char *fmt, va_list args);

void ortp_set_log_file(FILE *file);
void ortp_set_log_handler(OrtpLogFunc func);

VAR_DECLSPEC OrtpLogFunc ortp_logv_out;

extern unsigned int __ortp_log_mask;

#define ortp_log_level_enabled(level)	(__ortp_log_mask & (level))

#if !defined(WIN32) && !defined(_WIN32_WCE)
#define ortp_logv(level,fmt,args) \
{\
	if (ortp_logv_out!=NULL && ortp_log_level_enabled(level)) \
		ortp_logv_out(level,fmt,args);\
	if ((level)==ORTP_FATAL) abort();\
}while(0)
#else
void ortp_logv(int level, const char *fmt, va_list args);
#endif

void ortp_set_log_level_mask(int levelmask);

#ifdef ORTP_DEBUG_MODE
static inline void ortp_debug(const char *fmt,...)
{
  va_list args;
  va_start (args, fmt);
  ortp_logv(ORTP_DEBUG, fmt, args);
  va_end (args);
}
#else
#if defined(WIN32) || defined(_WIN32_WCE)
#define ortp_debug(...)
#else
static inline void ortp_debug(const char *fmt,...)
{
  va_list args;
  va_start (args, fmt);
  va_end (args);
}
#endif
#endif

#ifdef ORTP_NOMESSAGE_MODE

#define ortp_log(...)
#define ortp_message(...)
#define ortp_warning(...)

#else

static inline void ortp_log(OrtpLogLevel lev, const char *fmt,...){
	va_list args;
	va_start (args, fmt);
	ortp_logv(lev, fmt, args);
 	va_end (args);
}

static inline void ortp_message(const char *fmt,...)
{
  va_list args;
  va_start (args, fmt);
  ortp_logv(ORTP_MESSAGE, fmt, args);
  va_end (args);
}

static inline void ortp_warning(const char *fmt,...)
{
  va_list args;
  va_start (args, fmt);
  ortp_logv(ORTP_WARNING, fmt, args);
  va_end (args);
}

#endif

static inline void ortp_error(const char *fmt,...)
{
  va_list args;
  va_start (args, fmt);
  ortp_logv(ORTP_ERROR, fmt, args);
  va_end (args);
}

static inline void ortp_fatal(const char *fmt,...)
{
  va_list args;
  va_start (args, fmt);
  ortp_logv(ORTP_FATAL, fmt, args);
  va_end (args);
}


/****************/
/*statistics api*/
/****************/

extern rtp_stats_t ortp_global_stats;

void ortp_global_stats_reset(void);
rtp_stats_t *ortp_get_global_stats(void);

void ortp_global_stats_display(void);
void rtp_stats_display(const rtp_stats_t *stats, const char *header);
void rtp_stats_reset(rtp_stats_t *stats);

#ifdef __cplusplus
}
#endif

#endif
