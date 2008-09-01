/*
 * Startup tool for non statically mapped PCMCIA sockets
 *
 *  The initial developer of the original code is David A. Hinds
 *  <dahinds@users.sourceforge.net>.  Portions created by David A. Hinds
 *  are Copyright (C) 1999 David A. Hinds.  All Rights Reserved.
 *
 * License: GPL v2
 *
 */

#define MAX_SOCKS	8
#define MAX_BINDINGS	4
#define MAX_MODULES	4

/* for AdjustResourceInfo */
typedef struct adjust_t {
    unsigned int	Action;
    unsigned int	Resource;
    unsigned int	Attributes;
    union {
	struct memory {
	    unsigned long	Base;
	    unsigned long	Size;
	} memory;
	struct io {
	    unsigned long	BasePort;
	    unsigned long	NumPorts;
	    unsigned int	IOAddrLines;
	} io;
	struct irq {
	    unsigned int	IRQ;
	} irq;
    } resource;
} adjust_t;


typedef struct adjust_list_t {
	adjust_t		adj;
    struct adjust_list_t *next;
} adjust_list_t;


extern adjust_list_t	*root_adjust;

int parse_configfile(char *fn);


#define RES_MEMORY_RANGE		1
#define RES_IO_RANGE			2
#define RES_IRQ				3
#define RES_RESERVED			0x10
#define REMOVE_MANAGED_RESOURCE		1
#define ADD_MANAGED_RESOURCE		2
