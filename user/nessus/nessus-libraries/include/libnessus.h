/* Nessuslib -- the Nessus Library
 * Copyright (C) 1998 Renaud Deraison
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */   

#ifndef _NESSUS_NESSUSLIB_H
#define _NESSUS_NESSUSLIB_H
 

#ifndef ExtFunc
#define ExtFunc
#endif

ExtFunc void nessus_lib_version(int *, int *, int *);
 
/*
 * Arglist definition and defines
 */
 
struct arglist {
	char * name;
	int type;
	void * value;
	long length;
	struct arglist * next;
	int hash;
	};

	
#define ARG_STRING 	1
#define ARG_PTR 	2
#define ARG_INT 	3
#define ARG_ARGLIST 	4
#define ARG_STRUCT	5


/*
 * Plugin standard function templates
 */

typedef int(*plugin_init_t)(struct arglist *);
typedef int(*plugin_run_t)(struct arglist *);      





/*
 * Network-related functions
 */

/* Plugin specific network functions */
ExtFunc int open_sock_tcp(struct arglist * , unsigned int, int );
ExtFunc int open_sock_udp(struct arglist * , unsigned int );
ExtFunc int open_sock_option(struct arglist * , unsigned int , int , int, int);
ExtFunc int recv_line(int, char *, size_t);
ExtFunc int nrecv(int, void*, int, int);
ExtFunc int is_cgi_installed(struct arglist * , const char *);
ExtFunc int is_cgi_installed_by_port(struct arglist * , const char *, int);
ExtFunc int socket_close(int);

/* Additional functions -- should not be used by the plugins */
ExtFunc int open_sock_tcp_hn(const char * , unsigned int );
ExtFunc int open_sock_opt_hn(const char * , unsigned int , int , int, int );
ExtFunc struct in_addr nn_resolve (const char *); 

#ifdef __GNUC__
ExtFunc void auth_printf(struct arglist *, char * , ...) __attribute__ (( format (printf, 2, 3)));
#else
ExtFunc void auth_printf(struct arglist *, char * , ...);
#endif
ExtFunc void scanner_add_port(struct arglist*, int, char *);
ExtFunc void auth_send(struct arglist *, char *);
ExtFunc char * auth_gets(struct arglist *, char * , size_t);
ExtFunc int ping_host(struct in_addr);

/* 
 * Management of the arglists --should not be used directly by
 * the plugins
 */

ExtFunc void arg_add_value(struct arglist *, const char *, int, long, void *);	   
ExtFunc int arg_set_value(struct arglist *, const char *, long, void *);	
ExtFunc int arg_set_type(struct arglist *, const char *, int);
ExtFunc void * arg_get_value(struct arglist *, const char *);
ExtFunc int arg_get_type(struct arglist *, const char *);
ExtFunc int arg_get_length(struct arglist *, const char *);
ExtFunc void arg_dump(struct arglist *, int);
ExtFunc void arg_dup(struct arglist *, struct arglist *);
ExtFunc void arg_free(struct arglist *);
ExtFunc void arg_free_all(struct arglist *);
ExtFunc void arg_free_name(char*);



/*
 * Arglist management at plugin-level
 */
 
ExtFunc void plug_set_name(struct arglist *, const char *, const char *);
ExtFunc char*plug_get_name(struct arglist*);

ExtFunc void plug_set_path(struct arglist *, const char *);
ExtFunc char*plug_get_path(struct arglist *);

ExtFunc void plug_set_fname(struct arglist *, const char *);
ExtFunc char*plug_get_fname(struct arglist *);


ExtFunc void plug_set_version(struct arglist *, const char *);
ExtFunc char*plug_get_version(struct arglist *);

ExtFunc void plug_set_timeout(struct arglist *, int);
ExtFunc int  plug_get_timeout(struct arglist *);

ExtFunc void plug_set_launch(struct arglist *, int);
ExtFunc int plug_get_launch(struct arglist *);

ExtFunc void plug_set_summary(struct arglist *, const char *, const char*);
ExtFunc char*plug_get_summary(struct arglist *);

ExtFunc void plug_set_description(struct arglist *, const char *,const char *);
ExtFunc char*plug_get_description(struct arglist *);

ExtFunc void plug_set_category(struct arglist *, int);
ExtFunc int  plug_get_category(struct arglist *);

ExtFunc void plug_set_copyright(struct arglist *, const char *, const char*);
ExtFunc char*plug_get_copyright(struct arglist *);

ExtFunc void plug_set_family(struct arglist * , const char *, const char *);
ExtFunc char*plug_get_family(struct arglist *);

ExtFunc	void plug_set_dep(struct arglist *, const char *);
ExtFunc struct arglist * plug_get_deps(struct arglist*);

ExtFunc void plug_set_id(struct arglist *, int);
ExtFunc int  plug_get_id(struct arglist *);

ExtFunc void plug_set_cve_id(struct arglist *, char *);
ExtFunc char*plug_get_cve_id(struct arglist *);

ExtFunc void plug_set_bugtraq_id(struct arglist *, char *);
ExtFunc char*plug_get_bugtraq_id(struct arglist *);

ExtFunc void plug_set_xref(struct arglist *, char *, char *);
ExtFunc char * plug_get_xref(struct arglist *);

ExtFunc void plug_set_see_also(struct arglist *, char *);
ExtFunc struct arglist * plug_get_see_also(struct arglist *);

#ifdef HAVE_SSL
ExtFunc void plug_set_ssl_cert(struct arglist*, char*);
ExtFunc void plug_set_ssl_key(struct arglist*, char*);
ExtFunc void plug_set_ssl_pem_password(struct arglist*, char*);
ExtFunc int nessus_SSL_init(char*);
ExtFunc void sslerror(char*);
ExtFunc void nessus_install_passwd_cb(SSL_CTX*, char*);

#endif



ExtFunc void plug_add_dep(struct arglist *, char *, char *);

ExtFunc void plug_add_port(struct arglist *, int);

ExtFunc const char * plug_get_hostname(struct arglist *);
ExtFunc const char * plug_get_host_fqdn(struct arglist *);
ExtFunc unsigned int plug_get_host_open_port(struct arglist * desc);
ExtFunc void plug_add_host(struct arglist *, struct arglist *);

ExtFunc char* plug_get_cve_id(struct arglist*);
ExtFunc char* plug_get_bugtraq_id(struct arglist*);

ExtFunc void plug_require_key(struct arglist *, const char *);
ExtFunc struct arglist * plug_get_required_keys(struct arglist *);

ExtFunc void plug_exclude_key(struct arglist *, const char *);
ExtFunc struct arglist * plug_get_excluded_keys(struct arglist *);

ExtFunc void plug_require_port(struct arglist *, const char *);
ExtFunc struct arglist * plug_get_required_ports(struct arglist *);

ExtFunc void plug_require_udp_port(struct arglist*, const char *);
ExtFunc struct arglist * plug_get_required_udp_ports(struct arglist *);

ExtFunc int plug_get_port_transport(struct arglist*, int);
ExtFunc int comm_send_status(struct arglist*, char*, char*, int, int);
ExtFunc int islocalhost(struct in_addr *);



/*
 * Reporting functions
 */
 
/* Plugin-specific : */
ExtFunc void proto_post_hole(struct arglist *, int, const char *, const char *);
ExtFunc void post_hole(struct arglist *, int, const char *);
ExtFunc void post_hole_udp(struct arglist *, int, const char *);
#define post_hole_tcp post_hole

ExtFunc void proto_post_info(struct arglist *, int, const char *, const char *);
ExtFunc void post_info(struct arglist *, int, const char *);
ExtFunc void post_info_udp(struct arglist *, int, const char *);
#define post_info_tcp post_info

ExtFunc void proto_post_note(struct arglist *, int, const char *, const char *);
ExtFunc void post_note(struct arglist *, int, const char *);
ExtFunc void post_note_udp(struct arglist *, int, const char *);
#define post_note_tcp post_note

#ifndef _WIN32
/* returns a full duplex data file stream */
ExtFunc FILE * ptyexecvp (const char *file, const char **argv, pid_t *child);
#endif /* _WIN32 */
ExtFunc char ** append_argv (char **argv, char *opt);
ExtFunc void    destroy_argv (char **argv);
ExtFunc void (*pty_logger(void(*)(const char *, ...)))(const char *, ...);

ExtFunc FILE*	nessus_popen(const char*, const char**, pid_t*);
ExtFunc int	nessus_pclose(FILE*, pid_t);

/* 
 * Management of the portlists
 */


ExtFunc void host_add_port(struct arglist *, int, int);
ExtFunc void host_add_port_udp(struct arglist *, int, int);
ExtFunc int host_get_port_state(struct arglist *, int);
ExtFunc int host_get_port_state_udp(struct arglist *, int);
/* Not implemented
char * host_get_port_banner(struct arglist *, int);
*/






/*
 * Miscellaneous functions
 */
 
ExtFunc struct in_addr * plug_get_host_ip(struct arglist *);
ExtFunc char * plug_get_host_name(struct arglist *);
ExtFunc char * get_preference(struct arglist *, const char *);
#define PREF_CHECKBOX "checkbox"
#define PREF_ENTRY "entry"
#define PREF_RADIO "radio"
#define PREF_PASSWORD "password"
#define PREF_FILE "file"
ExtFunc void add_plugin_preference(struct arglist *, const char *, const char *, const char *);
ExtFunc char *get_plugin_preference(struct arglist *, const char *);
ExtFunc const char *get_plugin_preference_fname(struct arglist*, const char*);

/*
 * Replacement for system related functions
 */
 


ExtFunc void * emalloc(size_t);
ExtFunc char * estrdup(const char *);
ExtFunc void * erealloc(void*, size_t);
ExtFunc void efree(void *);
ExtFunc size_t estrlen(const char *, size_t);


#ifdef HUNT_MEM_LEAKS
ExtFunc void * __hml_malloc(char*, int, size_t);
ExtFunc char * __hml_strdup(char*, int, char*);
ExtFunc void   __hml_free(char*, int, void*);
ExtFunc void * __hml_realloc(char*, int, void*, size_t);



#define emalloc(x) __hml_malloc(__FILE__, __LINE__, x)
#define estrdup(x) __hml_strdup(__FILE__, __LINE__, x)
#define efree(x)   __hml_free(__FILE__, __LINE__, x)

#undef strdup

#define malloc(x) __hml_malloc(__FILE__, __LINE__, x)
#define strdup(x) __hml_strdup(__FILE__, __LINE__, x)
#define free(x)   __hml_free(__FILE__, __LINE__, &x)
#define realloc(x, y) __hml_realloc(__FILE__, __LINE__, x, y)

#endif

/* 
 * Inter Plugins Communication functions
 */
ExtFunc void plug_set_key(struct arglist *, char *, int, void *);
ExtFunc void * plug_get_key(struct arglist *, char *);
/*
 * FTP Functions
 */
ExtFunc int ftp_log_in(int , char * , char * );
ExtFunc int ftp_get_pasv_address(int , struct sockaddr_in * );


ExtFunc char* addslashes(char*);
ExtFunc char* rmslashes(char*);

ExtFunc char* nessuslib_version();



/*
 * Pcap utils
 */
#include <pcap.h>
 
ExtFunc int get_datalink_size(int);
ExtFunc char *routethrough(struct in_addr *, struct in_addr *);

ExtFunc int is_local_ip(struct in_addr);

ExtFunc int get_mac_addr(struct in_addr, char**);

/* 
 * Misc. defines
 */
/* Actions types of the plugins */
#define ACT_LAST		ACT_END
#define ACT_FIRST		ACT_INIT

#define ACT_END			9
#define ACT_KILL_HOST		8
#define ACT_DENIAL 		7
#define ACT_DESTRUCTIVE_ATTACK 	6
#define ACT_MIXED_ATTACK 	5
#define ACT_ATTACK 		4
#define ACT_GATHER_INFO 	3
#define ACT_SETTINGS		2
#define ACT_SCANNER 		1
#define ACT_INIT		0





/*
 * Type of "transport layer", for encapsulated connections
 * Only SSL is supported at this time.
 * (Bad) examples of other layers could be SOCKS, httptunnel, icmptunnel,
 * RMI over HTTP, DCOM over HTTP, TCP over TCP, etc.
 */
#define NESSUS_ENCAPS_IP	1
#define NESSUS_ENCAPS_SSLv23	2 /* Ask for compatibility options */
#define NESSUS_ENCAPS_SSLv2	3
#define NESSUS_ENCAPS_SSLv3	4
#define NESSUS_ENCAPS_TLSv1	5

#define IS_ENCAPS_SSL(x) ((x) >= NESSUS_ENCAPS_SSLv23 && (x) <= NESSUS_ENCAPS_TLSv1)

/*
 * Transport layer options 
 */
#define NESSUS_CNX_IDS_EVASION_SPLIT	1L  /* Try to evade NIDS by spliting sends */
#define NESSUS_CNX_IDS_EVASION_INJECT	2L /* Split + insert garbage */
#define NESSUS_CNX_IDS_EVASION_SHORT_TTL 4L /* Split + too short ttl for garbage */
#define NESSUS_CNX_IDS_EVASION_FAKE_RST  8L /* Send a fake RST from our end after each established connection */

#define NESSUS_CNX_IDS_EVASION_SEND_MASK (NESSUS_CNX_IDS_EVASION_SPLIT|NESSUS_CNX_IDS_EVASION_INJECT|NESSUS_CNX_IDS_EVASION_SHORT_TTL)


ExtFunc int    open_stream_connection(struct arglist *, unsigned int, int, int);
ExtFunc int    open_stream_connection_unknown_encaps(struct arglist *, unsigned int, int, int *);
ExtFunc int    open_stream_auto_encaps(struct arglist *, unsigned int, int);
ExtFunc int    write_stream_connection (int, void * buf, int n);
ExtFunc int    read_stream_connection (int, void *, int);
ExtFunc int    read_stream_connection_min(int, void*, int, int);
ExtFunc int    close_stream_connection(int);
ExtFunc int    nsend(int, void*, int, int);
ExtFunc const char* get_encaps_name(int);
ExtFunc const char* get_encaps_through(int);

ExtFunc int    stream_set_timeout(int, int);
ExtFunc int    stream_set_options(int, int, int);

#ifdef HAVE_SSL
ExtFunc        X509*   stream_get_server_certificate(int);
ExtFunc	       char*   stream_get_ascii_server_certificate(int);
#endif


ExtFunc	int 	is_shell_command_present(char*);
ExtFunc char* 	find_in_path(char*, int);

ExtFunc char*	build_encode_URL(struct arglist*, char*, char*, char*, char*);


#ifdef HAVE_SSL
ExtFunc int nessus_register_connection(int, SSL*);
#else
ExtFunc int nessus_register_connection(int, void*);
#endif
ExtFunc int nessus_deregister_connection(int);
ExtFunc int nessus_get_socket_from_connection(int);


ExtFunc void nessus_init_random();
ExtFunc int stream_zero(fd_set*);
ExtFunc int stream_set(int, fd_set*);
ExtFunc int stream_isset(int, fd_set*);


ExtFunc int bpf_server();
ExtFunc int bpf_open_live(char*, char*);
ExtFunc u_char* bpf_next(int, int *);
ExtFunc void bpf_close(int);

void initsetproctitle(int argc, char *argv[], char *envp[]);
#ifndef HAVE_SETPROCTITLE
void setproctitle( const char *fmt, ... );
#endif



ExtFunc struct in_addr socket_get_next_source_addr();
ExtFunc int set_socket_source_addr(int, int);
ExtFunc void socket_source_init(struct in_addr *);

struct arglist * store_plugin(struct arglist *, char *, char *);
struct arglist * store_load_plugin(char *, char *, char *, struct arglist*);
int		 store_init_sys(char *);
int		 store_init_user(char *);


int		nessus_init_svc();

#endif
