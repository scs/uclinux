#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>

#include <openobex/obex.h>

#include "ircp.h"
#include "ircp_io.h"
#include "ircp_server.h"
#include "debug.h"

#define TRUE  1
#define FALSE 0

//
// Incoming event from OpenOBEX
//
void srv_obex_event(obex_t *handle, obex_object_t *object, int mode, int event, int obex_cmd, int obex_rsp)
{
	ircp_server_t *srv;
	int ret;
		
	srv = OBEX_GetUserData(handle);
	// DEBUG(4, "\n");

	switch (event)	{
	case OBEX_EV_STREAMAVAIL:
		DEBUG(4, "Time to read some data from stream\n");
		ret = ircp_srv_receive(srv, object, FALSE);
		break;
	case OBEX_EV_PROGRESS:
		break;
	case OBEX_EV_REQ:
		DEBUG(4, "Incoming request %02x, %d\n", obex_cmd, OBEX_CMD_SETPATH);

		switch(obex_cmd) {
		case OBEX_CMD_CONNECT:
			srv->infocb(IRCP_EV_CONNECTIND, "");	
			ret = 1;
			break;
		case OBEX_CMD_DISCONNECT:
			srv->infocb(IRCP_EV_DISCONNECTIND, "");	
			ret = 1;
			break;

		case OBEX_CMD_PUT:
			ret = ircp_srv_receive(srv, object, TRUE);
			break;

		case OBEX_CMD_SETPATH:
			ret = ircp_srv_setpath(srv, object);
			break;
		default:
			ret = 1;
			break;
		}

		if(ret < 0) {
			srv->finished = TRUE;
			srv->success = FALSE;
		}
			
		break;

	case OBEX_EV_REQHINT:
		/* An incoming request is about to come. Accept it! */
		switch(obex_cmd) {
		case OBEX_CMD_PUT:
			DEBUG(4, "Going to turn streaming on!\n");
			/* Set response to ok! */
			OBEX_ObjectSetRsp(object, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
			/* Turn streaming on */
			OBEX_ObjectReadStream(handle, object, NULL);
			break;
		
		case OBEX_CMD_SETPATH:
		case OBEX_CMD_CONNECT:
		case OBEX_CMD_DISCONNECT:
			/* Set response to ok! */
			OBEX_ObjectSetRsp(object, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
			break;
		
		default:
			DEBUG(0, "Skipping unsupported command:%02x\n", obex_cmd);
			OBEX_ObjectSetRsp(object, OBEX_RSP_NOT_IMPLEMENTED, OBEX_RSP_NOT_IMPLEMENTED);
			break;
		
		}
		break;

	case OBEX_EV_REQDONE:
		if(obex_cmd == OBEX_CMD_DISCONNECT) {
			srv->finished = TRUE;
			srv->success = TRUE;
		}
		break;

	case OBEX_EV_LINKERR:
		DEBUG(0, "Link error\n");
		srv->finished = TRUE;
		srv->success = FALSE;
		break;
	default:
		break;
	}
}

//
//
//
int ircp_srv_sync_wait(ircp_server_t *srv)
{
	int ret;
	while(srv->finished == FALSE) {
		ret = OBEX_HandleInput(srv->obexhandle, 1);
		if (ret < 0)
			return -1;
	}
	if(srv->success)
		return 1;
	else
		return -1;
}

//
// Change current dir after some sanity-checking
//
int ircp_srv_setpath(ircp_server_t *srv, obex_object_t *object)
{
	obex_headerdata_t hv;
	uint8_t hi;
	int hlen;

	uint8_t *nonhdr_data = NULL;
	int nonhdr_data_len;
	char *name = NULL;
	int ret = -1;

	DEBUG(4, "\n");
	nonhdr_data_len = OBEX_ObjectGetNonHdrData(object, &nonhdr_data);
	if(nonhdr_data_len != 2) {
		DEBUG(0, "Error parsing SetPath-command\n");
		return -1;
	}

	while(OBEX_ObjectGetNextHeader(srv->obexhandle, object, &hi, &hv, &hlen))	{
		switch(hi)	{
		case OBEX_HDR_NAME:
			if( (name = malloc(hlen / 2)))	{
				OBEX_UnicodeToChar(name, hv.bs, hlen);
			}
			break;
		default:
			DEBUG(2, "Skipped header %02x\n", hi);
		}
	}

	DEBUG(2, "Got setpath flags=%d, name=%s\n", nonhdr_data[0], name);

	// If bit 0 is set we shall go up
	if(nonhdr_data[0] & 1) {
		/* Cannot cd above inbox */
		if(srv->dirdepth == 0)
			goto out;
		
		if(chdir("..") == -1)
			goto out;

		srv->dirdepth--;
	}
	else {
		if(name == NULL)
			goto out;
		
		// A setpath with empty name meens "goto root"
		if(strcmp(name, "") == 0) {
			if(chdir(srv->inbox) == -1)
				goto out;
			srv->dirdepth = 0;
		}
		else {
			DEBUG(4, "Going down to %s\n", name);
			if(ircp_checkdir("", name, CD_CREATE) < 0)
				goto out;
			if(chdir(name) == -1)
				goto out;
			srv->dirdepth++;		
		}
	}
				
	ret = 1;

out:
	if(ret < 0)
		OBEX_ObjectSetRsp(object, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
	free(name);
	return ret;
}


//
// Open a file for receivning
//
static int new_file(ircp_server_t *srv, obex_object_t *object)
{
	obex_headerdata_t hv;
	uint8_t hi;
	int hlen;
	char *name = NULL;
	int ret = -1;

	/* First iterate through recieved header to find name */
	while(OBEX_ObjectGetNextHeader(srv->obexhandle, object, &hi, &hv, &hlen))	{
		switch(hi)	{
		case OBEX_HDR_NAME:
			if( (name = malloc(hlen / 2)))	{
				OBEX_UnicodeToChar(name, hv.bs, hlen);
			}
			break;
		default:
			DEBUG(4, "Skipped header %02x\n", hi);
		}
	}
	if(name == NULL)	{
		DEBUG(0, "Got a PUT without a name. Refusing\n");
		/* Send back error */
		OBEX_ObjectSetRsp(object, OBEX_RSP_BAD_REQUEST, OBEX_RSP_BAD_REQUEST);
		srv->infocb(IRCP_EV_ERR, "");
		goto out;
	}

	srv->infocb(IRCP_EV_RECEIVING, name);	
	srv->fd = ircp_open_safe("", name);
	
	ret = srv->fd;

out:	free(name);
	return ret;
}

//
// Extract interesting things from object and save to disk.
//
int ircp_srv_receive(ircp_server_t *srv, obex_object_t *object, int finished)
{
	const uint8_t *body = NULL;
	int body_len = 0;

	if(srv->fd < 0 && finished == FALSE) {
		/* Not receiving a file */
		if(new_file(srv, object) < 0)
			return 1;
	}
	
	if(finished == TRUE) {
        	/* Recieve done! */
		DEBUG(4, "Done!...\n");
		return 1;		
	}
	else if (srv->fd > 0) {
		/* fd is valid. We are currently receiving a file */
		body_len = OBEX_ObjectReadStream(srv->obexhandle, object, &body);
		DEBUG(4, "Got %d bytes of stream-data\n", body_len);
		
		if(body_len < 0) {
			/* Error */
		}
		else if(body_len == 0) {
			/* EOS */
			close(srv->fd);
	        	srv->fd = -1;
			srv->infocb(IRCP_EV_OK, "");
		}
		else {
			if(srv->fd > 0)
				write(srv->fd, body, body_len);
		}
		return 1;
	}
	return -1;
}	

//
// Create an ircp server
//
ircp_server_t *ircp_srv_open(ircp_info_cb_t infocb)
{
	ircp_server_t *srv;

	DEBUG(4, "\n");
	srv = malloc(sizeof(ircp_server_t));
	if(srv == NULL)
		return NULL;

	srv->fd = -1;
	srv->infocb = infocb;

#ifdef DEBUG_TCP
	srv->obexhandle = OBEX_Init(OBEX_TRANS_INET, srv_obex_event, 0);
#else
	srv->obexhandle = OBEX_Init(OBEX_TRANS_IRDA, srv_obex_event, 0);
#endif

	if(srv->obexhandle == NULL) {
		free(srv);
		return NULL;
	}
	OBEX_SetUserData(srv->obexhandle, srv);
	return srv;
}

//
// Close an ircp server
//
void ircp_srv_close(ircp_server_t *srv)
{
	DEBUG(4, "\n");
	ircp_return_if_fail(srv != NULL);

	OBEX_Cleanup(srv->obexhandle);
	free(srv);
}

//
// Wait for incoming files.
//
int ircp_srv_recv(ircp_server_t *srv, char *inbox)
{
	int ret;
	
	if(ircp_checkdir("", inbox, CD_ALLOWABS) < 0) {
		srv->infocb(IRCP_EV_ERRMSG, "Specified desination directory does not exist.");
		return -1;
	}

	/* Start receiving files in inbox */
	if(chdir(inbox) == -1)
		return -1;
	srv->dirdepth = 0;
			
	if(IrOBEX_ServerRegister(srv->obexhandle, "OBEX:IrXfer") < 0)
		return -1;
	srv->infocb(IRCP_EV_LISTENING, "");
	srv->inbox = inbox;
	
	ret = ircp_srv_sync_wait(srv);
	
	/* Go back to inbox */
	chdir(inbox);
	
	return ret;
}
