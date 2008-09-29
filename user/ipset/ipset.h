#ifndef __IPSET_H
#define __IPSET_H

/* Copyright 2000-2004 Joakim Axelsson (gozem@linux.nu)
 *                     Patrick Schaaf (bof@bof.de)
 *                     Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * This program is free software; you can redistribute it and/or modify   
 * it under the terms of the GNU General Public License as published by   
 * the Free Software Foundation; either version 2 of the License, or      
 * (at your option) any later version.                                    
 *                                                                         
 * This program is distributed in the hope that it will be useful,        
 * but WITHOUT ANY WARRANTY; without even the implied warranty of         
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          
 * GNU General Public License for more details.                           
 *                                                                         
 * You should have received a copy of the GNU General Public License      
 * along with this program; if not, write to the Free Software            
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <getopt.h>
#include <sys/types.h>
#include <netdb.h>

#include <linux/netfilter_ipv4/ip_set.h>

#define IPSET_LIB_NAME "/libipset_%s.so"
#define PROC_SYS_MODPROBE "/proc/sys/kernel/modprobe"

#define LIST_TRIES 5

#ifdef IPSET_DEBUG
extern int option_debug;
#define DP(format, args...) if (option_debug) 			\
	do {							\
		fprintf(stderr, "%s: %s (DBG): ", __FILE__, __FUNCTION__);\
		fprintf(stderr, format "\n" , ## args);			\
	} while (0)
#else
#define DP(format, args...)
#endif

/* Commands */
enum set_commands {
	CMD_NONE,
	CMD_CREATE,		/* -N */
	CMD_DESTROY,		/* -X */
	CMD_FLUSH,		/* -F */
	CMD_RENAME,		/* -E */
	CMD_SWAP,		/* -W */
	CMD_LIST,		/* -L */
	CMD_SAVE,		/* -S */
	CMD_RESTORE,		/* -R */
	CMD_ADD,		/* -A */
	CMD_DEL,		/* -D */
	CMD_TEST,		/* -T */
	CMD_BIND,		/* -B */
	CMD_UNBIND,		/* -U */
	CMD_HELP,		/* -H */
	CMD_VERSION,		/* -V */
	NUMBER_OF_CMD = CMD_VERSION,
	/* Internal commands */
	CMD_MAX_SETS,
	CMD_LIST_SIZE,
	CMD_SAVE_SIZE,
	CMD_ADT_GET,
};

enum exittype {
	OTHER_PROBLEM = 1,
	PARAMETER_PROBLEM,
	VERSION_PROBLEM
};

/* The view of an ipset in userspace */
struct set {
	char name[IP_SET_MAXNAMELEN];		/* Name of the set */
	ip_set_id_t id;				/* Unique set id */
	ip_set_id_t index;			/* Array index */
	unsigned ref;				/* References in kernel */
	struct settype *settype;		/* Pointer to set type functions */
};

struct settype {
	struct settype *next;

	char typename[IP_SET_MAXNAMELEN];

	int protocol_version;

	/*
	 * Create set
	 */

	/* Size of create data. Will be sent to kernel */
	size_t create_size;

	/* Initialize the create. */
	void (*create_init) (void *data);

	/* Function which parses command options; returns true if it ate an option */
	int (*create_parse) (int c, char *argv[], void *data,
			     unsigned *flags);

	/* Final check; exit if not ok. */
	void (*create_final) (void *data, unsigned int flags);

	/* Pointer to list of extra command-line options for create */
	struct option *create_opts;

	/*
	 * Add/del/test IP
	 */

	/* Size of data. Will be sent to kernel */
	size_t adt_size;

	/* Function which parses command options */
	ip_set_ip_t (*adt_parser) (unsigned cmd, const char *optarg, void *data);

	/*
	 * Printing
	 */

	/* Size of header. */
	size_t header_size;

	/* Initialize the type-header */
	void (*initheader) (struct set *set, const void *data);

	/* Pretty print the type-header */
	void (*printheader) (struct set *set, unsigned options);

	/* Pretty print all IPs */
	void (*printips) (struct set *set, void *data, size_t len, unsigned options);

	/* Pretty print all IPs sorted */
	void (*printips_sorted) (struct set *set, void *data, size_t len, unsigned options);

	/* Print save arguments for creating the set */
	void (*saveheader) (struct set *set, unsigned options);

	/* Print save for all IPs */
	void (*saveips) (struct set *set, void *data, size_t len, unsigned options);

	/* Conver a single IP (binding) to string */
	char * (*bindip_tostring)(struct set *set, ip_set_ip_t ip, unsigned options);
	
	/* Parse an IP at restoring bindings. FIXME */
	void (*bindip_parse) (const char *str, ip_set_ip_t * ip);

	/* Print usage */
	void (*usage) (void);

	/* Internal data */
	void *header;
	void *data;
	unsigned int option_offset;
	unsigned int flags;
};

extern void settype_register(struct settype *settype);

/* extern void unregister_settype(set_type_t *set_type); */

extern void exit_error(enum exittype status, char *msg, ...);

extern char *binding_ip_tostring(struct set *set,
				 ip_set_ip_t ip, unsigned options);
extern char *ip_tostring(ip_set_ip_t ip, unsigned options);
extern char *ip_tostring_numeric(ip_set_ip_t ip);
extern void parse_ip(const char *str, ip_set_ip_t * ip);
extern void parse_mask(const char *str, ip_set_ip_t * mask);
extern void parse_ipandmask(const char *str, ip_set_ip_t * ip,
			    ip_set_ip_t * mask);
extern char *port_tostring(ip_set_ip_t port, unsigned options);
extern void parse_port(const char *str, ip_set_ip_t * port);
extern int string_to_number(const char *str, unsigned int min, unsigned int max,
		            ip_set_ip_t *port);

extern void *ipset_malloc(size_t size);
extern char *ipset_strdup(const char *);
extern void ipset_free(void **data);

#define BITSPERBYTE	(8*sizeof(char))
#define ID2BYTE(id)	((id)/BITSPERBYTE)
#define ID2MASK(id)	(1 << ((id)%BITSPERBYTE))
#define test_bit(id, heap)	((((char *)(heap))[ID2BYTE(id)] & ID2MASK(id)) != 0)

#endif	/* __IPSET_H */
