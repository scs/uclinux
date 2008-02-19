/*
mediastreamer2 library - modular sound and video processing and streaming
Copyright (C) 2006  Simon MORLAT (simon.morlat@linphone.org)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/
#ifndef mscommon_h
#define mscommon_h

#include <ortp/ortp.h>

#define ms_malloc	ortp_malloc
#define ms_malloc0	ortp_malloc0
#define ms_realloc	ortp_realloc
#define ms_new		ortp_new
#define ms_new0		ortp_new0
#define ms_free		ortp_free
#define ms_strdup	ortp_strdup
#define ms_strdup_printf	ortp_strdup_printf

#define ms_mutex_t		ortp_mutex_t
#define ms_mutex_init		ortp_mutex_init
#define ms_mutex_destroy	ortp_mutex_destroy
#define ms_mutex_lock		ortp_mutex_lock
#define ms_mutex_unlock		ortp_mutex_unlock

#define ms_cond_t		ortp_cond_t
#define ms_cond_init		ortp_cond_init
#define ms_cond_wait		ortp_cond_wait
#define ms_cond_signal		ortp_cond_signal
#define ms_cond_broadcast	ortp_cond_broadcast
#define ms_cond_destroy		ortp_cond_destroy

#ifdef WIN32
static inline void ms_debug(const char *fmt,...)
{
  va_list args;
  va_start (args, fmt);
  ortp_logv(ORTP_DEBUG, fmt, args);
  va_end (args);
}
#else
#ifdef DEBUG
static inline void ms_debug(const char *fmt,...)
{
  va_list args;
  va_start (args, fmt);
  ortp_logv(ORTP_DEBUG, fmt, args);
  va_end (args);
}
#else
#define ms_debug(...)
#endif	
#endif



#define ms_message	ortp_message
#define ms_warning	ortp_warning
#define ms_error	ortp_error
#define ms_fatal	ortp_fatal

#define ms_return_val_if_fail(_expr_,_ret_)\
	if (!(_expr_)) { ms_error("assert "#_expr_ "failed"); return (_ret_);}

#define ms_return_if_fail(_expr_) \
	if (!(_expr_)){ ms_error("assert "#_expr_ "failed"); return ;}

#define ms_thread_t		ortp_thread_t
#define ms_thread_create 	ortp_thread_create
#define ms_thread_join		ortp_thread_join
#define ms_thread_exit		ortp_thread_exit

struct _MSList {
	struct _MSList *next;
	struct _MSList *prev;
	void *data;
};

typedef struct _MSList MSList;


#define ms_list_next(elem) ((elem)->next)


#ifdef __cplusplus
extern "C"{
#endif

MSList * ms_list_append(MSList *elem, void * data);
MSList * ms_list_prepend(MSList *elem, void * data);
MSList * ms_list_free(MSList *elem);
MSList * ms_list_concat(MSList *first, MSList *second);
MSList * ms_list_remove(MSList *first, void *data);
int ms_list_size(const MSList *first);
void ms_list_for_each(const MSList *list, void (*func)(void *));
void ms_list_for_each2(const MSList *list, void (*func)(void *, void *), void *user_data);
MSList *ms_list_remove_link(MSList *list, MSList *elem);
MSList *ms_list_find(MSList *list, void *data);
MSList *ms_list_find_custom(MSList *list, int (*compare_func)(const void *, const void*), void *user_data);
void * ms_list_nth_data(const MSList *list, int index);
int ms_list_position(const MSList *list, MSList *elem);
int ms_list_index(const MSList *list, void *data);
MSList *ms_list_insert_sorted(MSList *list, void *data, int (*compare_func)(const void *, const void*));


#undef MIN
#define MIN(a,b)	((a)>(b) ? (b) : (a))
#undef MAX
#define MAX(a,b)	((a)>(b) ? (a) : (b))


void ms_init(void);
int ms_load_plugins(const char *directory);
void ms_exit(void);

struct _MSSndCardDesc;

void ms_reload_snd_card(struct _MSSndCardDesc *snd_desc);


#ifdef __cplusplus
}
#endif

#endif
