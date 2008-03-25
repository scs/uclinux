#include <string.h>

#include "debug.h"
#include "ircp.h"
#include "ircp_client.h"
#include "ircp_server.h"


//
//
//
void ircp_info_cb(int event, char *param)
{
	DEBUG(4, "\n");
	switch (event) {

	case IRCP_EV_ERRMSG:
		printf("Error: %s\n", param);
		break;

	case IRCP_EV_ERR:
		printf("failed\n");
		break;
	case IRCP_EV_OK:
		printf("done\n");
		break;


	case IRCP_EV_CONNECTING:
		printf("Connecting...");
		break;
	case IRCP_EV_DISCONNECTING:
		printf("Disconnecting...");
		break;
	case IRCP_EV_SENDING:
		printf("Sending %s...", param);
		break;
	case IRCP_EV_RECEIVING:
		printf("Receiving %s...", param);
		break;

	case IRCP_EV_LISTENING:
		printf("Waiting for incoming connection\n");
		break;

	case IRCP_EV_CONNECTIND:
		printf("Incoming connection\n");
		break;
	case IRCP_EV_DISCONNECTIND:
		printf("Disconnecting\n");
		break;



	}
}

//
//
//
int main(int argc, char *argv[])
{
	int i;
	ircp_client_t *cli;
	ircp_server_t *srv;
	char *inbox;

	if(argc >= 2 && strcmp(argv[1], "-r") == 0) {
		srv = ircp_srv_open(ircp_info_cb);
		if(srv == NULL) {
			printf("Error opening ircp-server\n");
			return -1;
		}

		if(argc >= 3)
			inbox = argv[2];
		else
			inbox = ".";

		ircp_srv_recv(srv, inbox);
#ifdef DEBUG_TCP
		sleep(2);
#endif
		ircp_srv_close(srv);
	}
		

	else if(argc == 1) {
		printf("Usage: %s file1, file2, ...\n"
			"  or:  %s -r [DEST]\n\n"
			"Send files over IR. Use -r to receive files.\n", argv[0], argv[0]);
		return 0;
	}
	else {
		cli = ircp_cli_open(ircp_info_cb);
		if(cli == NULL) {
			printf("Error opening ircp-client\n");
			return -1;
		}
			
		// Connect
		if(ircp_cli_connect(cli) >= 0) {
			// Send all files
			for(i = 1; i < argc; i++) {
				ircp_put(cli, argv[i]);
			}

			// Disconnect
			ircp_cli_disconnect(cli);
		}
		ircp_cli_close(cli);
	}
	return 0;
}
