#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>

#include "cgiparse.h"

/*#define DEBUG_CGI*/

static char s_options[64];
static const char *s_data_name = 0;
static const char *s_options_name = 0;
static size_t s_len = 0;

static void data_writer(const char *name, const char *content_type, const char *buf, size_t len, off_t pos)
{
	if (pos == 0 && len == 0) {
#ifdef DEBUG_CGI
		/*printf("\nSECTION: name=%s, type=%s\n", name, content_type);*/
		syslog(LOG_INFO, "SECTION: name=%s, type=%s", name, content_type);
#endif
	}
	else {
		if (strcmp(name, s_data_name) == 0) {
#ifdef DEBUG_CGI
			/*printf("add_data(pos=%d, len=%d)\n", pos, len);*/
			syslog(LOG_INFO, "add_data(pos=%d, len=%d)\n", pos, len);
#endif
			add_data(pos, buf, len);
			s_len = pos + len;
		}
		else if (strcmp(name, s_options_name) == 0) {
			assert(len < sizeof(s_options));
			memcpy(s_options, buf, len);
			s_options[len] = 0;
#ifdef DEBUG_CGI
			/*printf("Got options: %s\n", s_options);*/
			syslog(LOG_INFO, "SECTION: options: %s = '%s'", name, s_options);
#endif
		}
		else {
#ifdef DEBUG_CGI
			syslog(LOG_ERR, "Unknown cgi section: %s (options=%s)\n", name, s_options_name);
#endif
		}
	}
}

/**
 * Returns length of data if OK, or 0 if error.
 * 
 */
size_t cgi_load(const char *data_name, const char *options_name, char options[64])
{
	int ret;

	s_data_name = data_name;
	s_options_name = options_name;

	ret = cgi_extract_sections(data_writer);
	if (ret == 0) {
		strcpy(options, s_options);
#ifdef DEBUG_CGI
		syslog(LOG_INFO, "Returning s_len=%d, options=%s", s_len, options);
#endif
		return(s_len);
	}
	return(0);
}
