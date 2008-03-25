#ifndef IRCP_SERVER_H
#define IRCP_SERVER_H

#include <openobex/obex.h>
#include "ircp.h"

typedef struct ircp_server
{
	obex_t *obexhandle;
	int finished;
	int success;
	char *inbox;
	ircp_info_cb_t infocb;
	int fd;
	int dirdepth;

} ircp_server_t;

int ircp_srv_receive(ircp_server_t *srv, obex_object_t *object, int finished);
int ircp_srv_setpath(ircp_server_t *srv, obex_object_t *object);

ircp_server_t *ircp_srv_open(ircp_info_cb_t infocb);
void ircp_srv_close(ircp_server_t *srv);
int ircp_srv_recv(ircp_server_t *srv, char *inbox);


#endif
