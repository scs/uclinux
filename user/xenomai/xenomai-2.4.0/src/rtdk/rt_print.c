/*
 * Copyright (C) 2007 Jan Kiszka <jan.kiszka@web.de>.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 */

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rtdk.h>
#include <asm/xenomai/system.h>

#define RT_PRINT_BUFFER_ENV		"RT_PRINT_BUFFER"
#define RT_PRINT_DEFAULT_BUFFER		16*1024

#define RT_PRINT_PERIOD_ENV		"RT_PRINT_PERIOD"
#define RT_PRINT_DEFAULT_PERIOD		100 /* ms */

#define RT_PRINT_LINE_BREAK		256

struct entry_head {
	FILE *dest;
	uint32_t seq_no;
	char text[1];
} __attribute__((packed));

struct print_buffer {
	off_t write_pos;

	struct print_buffer *next, *prev;

	void *ring;
	size_t size;

	char name[32];

	/*
	 * Keep read_pos separated from write_pos to optimise write
	 * caching on SMP.
	 */
	off_t read_pos;
};

struct print_buffer *__first_buffer;
uint32_t __seq_no;
size_t __default_buffer_size;
struct timespec __print_period;
int __auto_init;
pthread_mutex_t __buffer_lock;
pthread_key_t __buffer_key;

static void cleanup_buffer(struct print_buffer *buffer);
static void print_buffers(void);

/* *** rt_print API *** */

int rt_vfprintf(FILE *stream, const char *format, va_list args)
{
	struct print_buffer *buffer = pthread_getspecific(__buffer_key);
	off_t write_pos, read_pos;
	struct entry_head *head;
	int len;
	int res;

	if (!buffer) {
		res = 0;
		if (__auto_init)
			res = rt_print_init(0, NULL);
		else
			res = EIO;

		if (res) {
			errno = res;
			return -1;
		}
		buffer = pthread_getspecific(__buffer_key);
	}

	/* Take a snapshot of the ring buffer state */
	write_pos = buffer->write_pos;
	read_pos = buffer->read_pos;
	xnarch_read_memory_barrier();

	/* Is our write limit the end of the ring buffer? */
	if (write_pos >= read_pos) {
		/* Keep a savety margin to the end for at least an empty entry */
		len = buffer->size - write_pos - sizeof(struct entry_head);

		/* Special case: We were stuck at the end of the ring buffer
		   with space left there only for one empty entry. Now
		   read_pos was moved forward and we can wrap around. */
		if (len == 0 && read_pos > sizeof(struct entry_head)) {
			/* Write out empty entry */
			head = buffer->ring + write_pos;
			head->seq_no = __seq_no;
			head->text[0] = 0;

			/* Forward to the ring buffer start */
			write_pos = 0;
			len = read_pos - 1;
		}
	} else {
		/* Our limit is the read_pos ahead of our write_pos. One byte
		   margin is required to detect a full ring. */
		len = read_pos - write_pos - 1;
	}

	/* Account for head length */
	len -= sizeof(struct entry_head);
	if (len < 0)
		len = 0;

	head = buffer->ring + write_pos;

	res = vsnprintf(head->text, len, format, args);

	if (res < len) {
		/* Text was written completely, res contains its length */
		len = res;
	} else {
		/* Text was truncated, remove closing \0 that entry_head
		   already includes */
		len--;
	}

	/* If we were able to write some text, finalise the entry */
	if (len > 0) {
		head->seq_no = ++__seq_no;
		head->dest = stream;

		/* Move forward by text and head length */
		write_pos += len + sizeof(struct entry_head);
	}

	/* Wrap around early if there is more space on the other side */
	if (write_pos >= buffer->size - RT_PRINT_LINE_BREAK &&
	    read_pos <= write_pos && read_pos > buffer->size - write_pos) {
		/* An empty entry marks the wrap-around */
		head = buffer->ring + write_pos;
		head->seq_no = __seq_no;
		head->text[0] = 0;

		write_pos = 0;
	}

	/* All entry data must be written before we can update write_pos */
	xnarch_write_memory_barrier();

	buffer->write_pos = write_pos;

	return res;
}

int rt_vprintf(const char *format, va_list args)
{
	return rt_vfprintf(stdout, format, args);
}

int rt_fprintf(FILE *stream, const char *format, ...)
{
	va_list args;
	int n;

	va_start(args, format);
	n = rt_vfprintf(stream, format, args);
	va_end(args);

	return n;
}

int rt_printf(const char *format, ...)
{
	va_list args;
	int n;

	va_start(args, format);
	n = rt_vfprintf(stdout, format, args);
	va_end(args);

	return n;
}

static void set_buffer_name(struct print_buffer *buffer, const char *name)
{
	int n;

	n = sprintf(buffer->name, "%08lx", (unsigned long)pthread_self());
	if (name) {
		buffer->name[n++] = ' ';
		strncpy(buffer->name+n, name, sizeof(buffer->name)-n-1);
		buffer->name[sizeof(buffer->name)-1] = 0;
	}
}

int rt_print_init(size_t buffer_size, const char *buffer_name)
{
	struct print_buffer *buffer = pthread_getspecific(__buffer_key);
	size_t size = buffer_size;

	if (!size)
		size = __default_buffer_size;
	else if (size < RT_PRINT_LINE_BREAK)
		return EINVAL;

	if (buffer) {
		/* Only set name if buffer size is unchanged or default */
		if (size == buffer->size || !buffer_size) {
			set_buffer_name(buffer, buffer_name);
			return 0;
		}
		cleanup_buffer(buffer);
	}

	buffer = malloc(sizeof(*buffer));
	if (!buffer)
		return ENOMEM;

	buffer->ring = malloc(size);
	if (!buffer->ring) {
		free(buffer);
		return ENOMEM;
	}
	memset(buffer->ring, 0, size);

	buffer->read_pos  = 0;
	buffer->write_pos = 0;

	buffer->size = size;

	set_buffer_name(buffer, buffer_name);

	buffer->prev = NULL;

	pthread_mutex_lock(&__buffer_lock);

	buffer->next = __first_buffer;
	if (__first_buffer)
		__first_buffer->prev = buffer;
	__first_buffer = buffer;

	pthread_mutex_unlock(&__buffer_lock);

	pthread_setspecific(__buffer_key, buffer);

	return 0;
}

void rt_print_auto_init(int enable)
{
	__auto_init = enable;
}

void rt_print_cleanup(void)
{
	cleanup_buffer(pthread_getspecific(__buffer_key));
}

const char *rt_print_buffer_name(void)
{
	struct print_buffer *buffer = pthread_getspecific(__buffer_key);

	if (!buffer) {
		int res = -1;

		if (__auto_init)
			res = rt_print_init(0, NULL);

		if (res)
			return NULL;

		buffer = pthread_getspecific(__buffer_key);
	}

	return buffer->name;
}


/* *** Deferred Output Management *** */

static void cleanup_buffer(struct print_buffer *buffer)
{
	struct print_buffer *prev, *next;

	pthread_setspecific(__buffer_key, NULL);

	pthread_mutex_lock(&__buffer_lock);

	print_buffers();

	prev = buffer->prev;
	next = buffer->next;

	if (prev)
		prev->next = next;
	else
		__first_buffer = next;
	if (next)
		next->prev = prev;

	pthread_mutex_unlock(&__buffer_lock);

	free(buffer->ring);
	free(buffer);
}

static inline uint32_t get_next_seq_no(struct print_buffer *buffer)
{
	struct entry_head *head = buffer->ring + buffer->read_pos;
	return head->seq_no;
}

static struct print_buffer *get_next_buffer(void)
{
	struct print_buffer *pos = __first_buffer;
	struct print_buffer *buffer = NULL;
	uint32_t next_seq_no = 0; /* silence gcc... */

	while (pos) {
		if (pos->read_pos != pos->write_pos &&
		    (!buffer || get_next_seq_no(pos) < next_seq_no)) {
			buffer = pos;
			next_seq_no = get_next_seq_no(pos);
		}
		pos = pos->next;
	}

	return buffer;
}

static void print_buffers(void)
{
	struct print_buffer *buffer;
	struct entry_head *head;
	off_t read_pos;
	int len;

	while (1) {
		buffer = get_next_buffer();
		if (!buffer)
			break;

		read_pos = buffer->read_pos;
		head = buffer->ring + read_pos;
		len = strlen(head->text);

		if (len) {
			/* Print out non-empty entry and proceed */
			fprintf(head->dest, "%s", head->text);
			read_pos += sizeof(*head) + len;
		} else {
			/* Emptry entries mark the wrap-around */
			read_pos = 0;
		}

		/* Make sure we have read the entry competely before
		   forwarding read_pos */
		xnarch_read_memory_barrier();
		buffer->read_pos = read_pos;

		/* Enforce the read_pos update before proceeding */
		xnarch_write_memory_barrier();
	}
}

static void *printer_thread(void *arg)
{
	while (1) {
		nanosleep(&__print_period, NULL);

		pthread_mutex_lock(&__buffer_lock);

		print_buffers();

		pthread_mutex_unlock(&__buffer_lock);
	}
}

void __rt_print_init(void)
{
	pthread_t thread;
	pthread_attr_t thattr;
	const char *value_str;
	unsigned long long period;

	__first_buffer = NULL;
	__seq_no = 0;
	__auto_init = 0;

	__default_buffer_size = RT_PRINT_DEFAULT_BUFFER;
	value_str = getenv(RT_PRINT_BUFFER_ENV);
	if (value_str) {
		errno = 0;
		__default_buffer_size = strtol(value_str, NULL, 10);
		if (errno || __default_buffer_size < RT_PRINT_LINE_BREAK) {
			fprintf(stderr, "Invalid %s\n", RT_PRINT_BUFFER_ENV);
			exit(1);
		}
	}

	period = RT_PRINT_DEFAULT_PERIOD;
	value_str = getenv(RT_PRINT_PERIOD_ENV);
	if (value_str) {
		errno = 0;
		period = strtoll(value_str, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid %s\n", RT_PRINT_PERIOD_ENV);
			exit(1);
		}
	}
	__print_period.tv_sec  = period / 1000;
	__print_period.tv_nsec = (period % 1000) * 1000000;

	pthread_mutex_init(&__buffer_lock, NULL);
	pthread_key_create(&__buffer_key, (void (*)(void*))cleanup_buffer);

	pthread_attr_init(&thattr);
	pthread_attr_setstacksize(&thattr, PTHREAD_STACK_MIN);
	pthread_create(&thread, &thattr, printer_thread, NULL);
}
