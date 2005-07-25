#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>

#include "kmp.h"
#include "cgiparse.h"

#define MULTIPART_FORM_DATA "multipart/form-data;"
#define CONTENT_DISPOSITION "Content-Disposition:"
#define CONTENT_TYPE "Content-Type:"
#define OCTET_STREAM "application/octet-stream"

#ifdef DEBUG_CGI
#define DEBUG
#endif

#define MAX_HEADER_SIZE 128
#define MAX_NAME_SIZE  64
#define MAX_CONTENT_TYPE 54

#define OS_BUF_SIZE (4096 + MAX_HEADER_SIZE)

typedef struct {
	int in_section;
	char buf[OS_BUF_SIZE];
	size_t len;
	off_t pos;
	output_buffer_function *writer;
	char name[MAX_NAME_SIZE];
	char content_type[MAX_CONTENT_TYPE];
} output_section_t;

static int process_section(output_section_t *os);

static void flush_buffer(output_section_t *os, int all)
{
	if (os->len) {
		if (all) {
			/* We flush the entire buffer */
			os->writer(os->name, os->content_type, os->buf, os->len, os->pos - os->len);
			os->len = 0;
		}
		else if (os->len >= MAX_HEADER_SIZE) {
			/* We flush all except the last 256 bytes in case there is some of the boundary
			 * in the buffer
			 */
			os->writer(os->name, os->content_type, os->buf, os->len - MAX_HEADER_SIZE, os->pos - os->len);

			/* Now move everything else down */
			memmove(os->buf, os->buf + os->len - MAX_HEADER_SIZE, MAX_HEADER_SIZE);

			os->len = MAX_HEADER_SIZE;
		}
	}
}

static int getter_section(void *cookie)
{
	output_section_t *os = (output_section_t *)cookie;

	int ch = getchar();

	if (ch == EOF) {
		return(ch);
	}

	if (os->in_section) {
		if (os->pos == 0) {
			os->writer(os->name, os->content_type, 0, 0, 0);
		}
		/* We are in the correct section, so copy out this char first */
		os->buf[os->len++] = ch;
		os->pos++;
		if (os->len == sizeof(os->buf)) {
			flush_buffer(os, 0);
		}
	}

	return(ch);
}

int cgi_extract_sections(output_buffer_function *writer)
{
	unsigned char buf[MAX_SEARCH_SIZE + 3];
	int content_length;
	const char *p;
	const char *boundary;
	int boundary_length;
	int match;
	output_section_t os;

	p = getenv("REQUEST_METHOD");
	if (!p || strcmp(p, "POST") != 0) {
		syslog(LOG_WARNING, "cgi_filefetch not POST");
		return(-1);
	}

	p = getenv("CONTENT_LENGTH");
	if (!p || ((content_length = atoi(p)) == 0)) {
		syslog(LOG_WARNING, "cgi_filefetch bad content length");
		return(-1);
	}

	p = getenv("CONTENT_TYPE");

	if (strncmp(p, MULTIPART_FORM_DATA, sizeof(MULTIPART_FORM_DATA) - 1) != 0) {
		syslog(LOG_WARNING, "cgi_filefetch not type: %s", MULTIPART_FORM_DATA);
		return(-1);
	}

	/* Now search for boundary=XXX */
	p = strstr(p, "boundary=");
	if (!p) {
		syslog(LOG_WARNING, "cgi_filefetch bad or missing boundary specification");
		return(-1);
	}
	p = strchr(p, '=') + 1;

#ifdef DEBUG
	syslog(LOG_INFO, "Got boundary=[%s]\n", p);
#endif

	/* Now search for --<boundary>
	 * Note that we don't search for \r\n--<boundary> since
	 * sometimes?? the first \r\n is missing
	 */
	
	snprintf(buf, sizeof(buf), "--%s", p);

	boundary = buf;
	boundary_length = strlen(boundary);
	os.in_section = 0;
	os.len = 0;
	os.pos = 0;
	os.writer = writer;

	/* Now iterate through each item separated by the boundary */
	while ((match = KMP(boundary, boundary_length, getter_section, &os)) >= 0) {
		int ch1 = getchar();
		int ch2 = getchar();

		if (os.in_section) {
			/* We have been outputting this section. Back up by the boundary length
			 * (plus 2 for the \r\n) and flush the buffer
			 */
#ifdef DEBUG
			syslog(LOG_INFO, "reached end of section, match=%d, os.len=%d, os.pos=%d, boundary_length=%d\n", match, os.len, (int)os.pos, boundary_length);
#endif
			assert(os.len >= boundary_length + 2);
			os.pos -= boundary_length + 2;
			os.len -= boundary_length + 2;
			flush_buffer(&os, 1);
		}

#ifdef DEBUG
		syslog(LOG_INFO, "Found match at %d\n", match - boundary_length);
#endif

		if (ch1 == '\r' && ch2 == '\n') {
			/* we are at a boundary, so process this section */
			process_section(&os);
		}
		else if (ch1 == '-' && ch2 == '-') {
#ifdef DEBUG
			syslog(LOG_INFO, "This is the last section\n");
#endif
			break;
		}
#ifdef DEBUG
		else {
			syslog(LOG_INFO, "Warning: Ignoring section with unknown terminator: '%c%c'\n", ch1, ch2);
		}
#endif
	}

	return(0);
}

/**
 * Returns 1 if found a valid section or 0 if not.
 *
 * Also sets os->in_section, os->pos, os->name, os->content_type.
 */
static int process_section(output_section_t *os)
{
	/* Need to read lines ending in \r\n, processing the headers
	 * Headers are terminated by a blank line
	 */
	char buf[MAX_HEADER_SIZE];
	char *pt;

	os->name[0] = 0;
	os->content_type[0] = 0;
	os->in_section = 0;
	os->pos = 0;

	while (fgets(buf, sizeof(buf), stdin) != 0) {
		if (buf[0] == '\r') {
			/* Reached end of headers */
#ifdef DEBUG
			syslog(LOG_INFO, "End of headers\n");
#endif
			break;
		}
		/* Strip off any \r\n */
		pt = strchr(buf, '\r');
		if (pt) {
			*pt = 0;
		}

#ifdef DEBUG
		syslog(LOG_INFO, "HEADER: %s\n", buf);
#endif

		if (strncmp(buf, CONTENT_DISPOSITION, sizeof(CONTENT_DISPOSITION) - 1) == 0) {
			pt = strstr(buf, "name=\"");
			if (!pt) {
				syslog(LOG_WARNING, "Warning: %s with no name\n", CONTENT_DISPOSITION);
			}
			else {
				char *end;
				pt += 6;
				end = strchr(pt, '"');
				if (end) {
					*end = 0;
				}
				snprintf(os->name, sizeof(os->name), "%s", pt);
				os->in_section = 1;
			}
			continue;
		}
		if (strncmp(buf, CONTENT_TYPE, sizeof(CONTENT_TYPE) - 1) == 0) {
			pt = buf + sizeof(CONTENT_TYPE);

			snprintf(os->content_type, sizeof(os->content_type), "%s", pt);
			continue;
		}
		/* Ignore other headers */
	}

#ifdef DEBUG
	syslog(LOG_INFO, "Got matching name=%s, content_type=%s, contents to follow\n", os->name, os->content_type);
#endif

	return(os->in_section);
}
