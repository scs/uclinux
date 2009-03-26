#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

#include "support.h"

struct reader {
	struct {
		unsigned char * buffer;
		int fd;
	} conf;
	struct {
		unsigned char * buffer_start;
		unsigned char * buffer_end;
	} state;
};

void reader_init(struct reader * r, int fd) {
	r->conf.fd = fd;
	r->state.buffer_start = r->conf.buffer;
	r->state.buffer_end = r->conf.buffer;
	
	r->conf.buffer = malloc(4 * 1024);
}

void reader_exit(struct reader * r) {
}

inline unsigned char * reader_getChar(struct reader * r) {
	if (r->state.buffer_start == r->state.buffer_end) {
		int num_read = read(0, r->conf.buffer, sizeof r->conf.buffer);
		
		if (num_read <= 0)
			return 0;
		
		r->state.buffer_start = r->conf.buffer;
		r->state.buffer_end = r->conf.buffer + num_read;
	}
	
	r->state.buffer_start += 1;
	
	return r->state.buffer_start - 1;
}

struct writer {
	struct {
		int addr_width;
		int line_length;
		int group_size;
		char * format;
		unsigned char * line_buffer;
	} conf;
	struct {
		int bytes_written;
		int line_pos;
	} state;
};

void writer_init(struct writer * w) {
	w->conf.addr_width = 8;
	w->conf.line_length = 16;
	w->conf.group_size = 2;
	w->state.bytes_written = 0;
	w->state.line_pos = 0;
	
	asprintf(&w->conf.format, "%%%dx: ", w->conf.addr_width);
	w->conf.line_buffer = malloc(w->conf.line_length + 1);
}

inline void writer_putLine(struct writer * w) {
	w->conf.line_buffer[w->state.line_pos] = 0;
	
	until (w->state.line_pos == w->conf.line_length) {
		printf(w->state.line_pos % w->conf.group_size == 0 ? "   " : "  ");
		w->state.line_pos += 1;
	}
	
	printf("  %s\n", w->conf.line_buffer);
}

void writer_exit(struct writer * w) {
	if (w->state.line_pos > 0)
		writer_putLine(w);
	
	printf(w->state.bytes_written == 1 ? "%d Byte\n" : "%d Bytes\n", w->state.bytes_written);
}

inline void writer_putChar(struct writer * w, unsigned char c) {
	if (w->state.line_pos == w->conf.line_length) {
		writer_putLine(w);
		w->state.line_pos = 0;
	}
	
	if (w->state.line_pos == 0)
		printf(w->conf.format, w->state.bytes_written);
	else if (w->state.line_pos % w->conf.group_size == 0)
		printf(" ");
	
	printf("%02hhx", c);
	
	w->conf.line_buffer[w->state.line_pos] = 31 < c && c < 127 ? c : '.';
	
	w->state.line_pos += 1;
	w->state.bytes_written += 1;
}

int main(const int argc, const char ** argv)
{
	struct reader r;
	struct writer w;
	
	if (argc != 1) {
		fprintf(stderr, "No arguments are allowed!");
		return 1;
	}
	
	reader_init(&r, 0);
	writer_init(&w);
	
	loop {
		unsigned char * c = reader_getChar(&r);
		
		if (c == NULL || feof(stdout))
			break;
		
		writer_putChar(&w, *c);
	};
	
	reader_exit(&r);
	writer_exit(&w);
	
	return 0;
}
