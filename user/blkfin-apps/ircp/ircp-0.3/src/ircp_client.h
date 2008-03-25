#ifndef IRCP_CLIENT_H
#define IRCP_CLIENT_H

#include <openobex/obex.h>
#include "ircp.h"

typedef struct ircp_client
{
	obex_t *obexhandle;
	int finished;
	int success;
	int obex_rsp;
	ircp_info_cb_t infocb;
	int fd;
	uint8_t *buf;
} ircp_client_t;


ircp_client_t *ircp_cli_open(ircp_info_cb_t infocb);
void ircp_cli_close(ircp_client_t *cli);
int ircp_cli_connect(ircp_client_t *cli);
int ircp_cli_disconnect(ircp_client_t *cli);
int ircp_put(ircp_client_t *cli, char *name);
	
#endif
