/*----------------------------------------------------------------------

cgi-pro.c file
cgi library function prototype file
copyright (c) mistletoe technologies, inc., usa.
all rights reserved

written by deepak for red-hat linux (version: 2.4.20-8)
------------------------------------------------------------------------
while viewing in vi/vim editor, use ts=4
----------------------------------------------------------------------*/

/* user accessible macro(s) */
#define CGI_OK 0

/* shared data structures */
struct table_details
{
	int top_index;
	int bottom_index;
	int end_of_table;
};

/* user accessible function prototype(s) */
#ifdef __cplusplus
extern "C" {
#endif

char * get_data(int i_page_code, int i_session, short *s_error, unsigned long *ul_bytes, int *i_error_code, char *cp_command_buffer);
short set_data(int i_page_code, int i_session, char *cp_buffer, unsigned long ul_bytes, int *i_error_code, char *cp_command_buffer);
char * get_table(int i_page_code, int i_session, short *s_error, unsigned long *ul_bytes, int *i_error_code, char *cp_command_buffer, struct table_details *td);
void get_error_message(short s_error_code, char *cp_error_string);
void get_external_error_message(short s_error_code, char *cp_error_string);

#ifdef __cplusplus 
}
#endif
