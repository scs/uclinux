/*
 * Some of the code ripped from FX/Phenolite :-)
 *
 */

/*
 * Some of the code ripped from FX/Phenolite :-)
 *
 */

#include "hydra-mod.h"
#include "d3des.h"

#define CHALLENGESIZE 16

extern char *HYDRA_EXIT;
char *buf;

/*
 * Encrypt CHALLENGESIZE bytes in memory using a password.
 * Ripped from vncauth.c
 */

void
vncEncryptBytes(unsigned char *bytes, char *passwd)
{
    unsigned char key[8];
    int i;

    /* key is simply password padded with nulls */

    for (i = 0; i < 8; i++) {
	if (i < strlen(passwd)) {
	    key[i] = passwd[i];
	} else {
	    key[i] = 0;
	}
    }

    deskey(key, EN0);

    for (i = 0; i < CHALLENGESIZE; i += 8) {
	des(bytes+i, bytes+i);
    }
}

int start_vnc(int s,int port, unsigned char options,char *miscptr,FILE *fp) {
    char *empty = "";
    char *pass;

    if (strlen(pass = hydra_get_next_password()) == 0) pass = empty;

    if ((buf = hydra_receive_line(s)) == NULL) return 1;
    buf[CHALLENGESIZE] = 0;

    vncEncryptBytes(buf, pass);
    
    if (hydra_send(s, buf, CHALLENGESIZE, 0) < 0) {
        return 1;
    }
    free(buf);

    if ((buf = hydra_receive_line(s)) == NULL) return(1);
    switch (buf[3]) {
        case 0: hydra_report_found(port, "vnc", fp);
                hydra_completed_pair_found();
                free(buf);
                if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
                    return 3;
                return 1;
        case 1: free(buf);
                hydra_completed_pair();
                if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
                    return 3;
                return 1;
	case 2: free(buf);
	        if (debug) printf("DEBUG: VNC server is angry, waiting for a minute\n");
	        sleep(60);
                return 1;
        default: free(buf);
                fprintf(stderr, "Error: unknown VNC server response\n");
                return 1;
    }

    return 1; // never reached
}

void service_vnc(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port) {
    int run = 1, next_run, sock = -1;
    int myport = PORT_VNC, mysslport = PORT_VNC_SSL;

    hydra_register_socket(sp);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return;
    while(1) {
        switch(run) {
            case 1: /* connect and service init function */
                    if (sock >= 0)
                        sock = hydra_disconnect(sock);
                    usleep(300000);
                    if ((options & OPTION_SSL) == 0) {
                        if (port != 0) myport = port;
                        sock = hydra_connect_tcp(ip, myport);
			port = myport;
                    } else {
                        if (port != 0) mysslport = port;
                        sock = hydra_connect_ssl(ip, mysslport);
			port = mysslport;
                    }
                    if (sock < 0) {
                        fprintf(stderr, "Error: Child with pid %d terminating, can not connect\n", (int)getpid());
                        hydra_child_exit();
                    }
                    buf = hydra_receive_line(sock);
                    if (buf == NULL) { /* check the first line */
                        fprintf(stderr,"Error: Not an VNC protocol or service shutdown: %s\n", buf);
                        hydra_child_exit();
                        exit(-1);
                    }
                    hydra_send(sock, buf, strlen(buf), 0);
                    free(buf);
                    buf = hydra_receive_line(sock);
                    if (buf == NULL) { /* check the first line */
                        fprintf(stderr,"Error: Not an VNC protocol or service shutdown: %s\n", buf);
                        hydra_child_exit();
                        exit(-1);
                    }
                    next_run = 2;
                    switch(buf[3]) {
                       case 0: 
                            fprintf(stderr,"Error: VNC server told us to quit\n");
                            hydra_child_exit();
                            exit(-1);
                       case 1:
                            fprintf(fp, "VNC server does not require authentication.\n");
                            printf("VNC server does not require authentication.\n");
                            hydra_child_exit();
                            exit(-1);
                       case 2:
                            break;
                       default:
                            fprintf(stderr,"Error: unknown VNC authentication type\n");
                            hydra_child_exit();
                            exit(-1);
                    }
                    
                    free(buf);
                    break;
            case 2: /* run the cracking function */
                    next_run = start_vnc(sock, port, options, miscptr, fp);
                    break;
            case 3: /* clean exit */
                    if (sock >= 0) sock = hydra_disconnect(sock);
                    hydra_child_exit();
                    return;
            default: fprintf(stderr,"Caught unknown return code, exiting!\n");
                     hydra_child_exit();
                     exit(-1);
        }
        run = next_run;
    }
}
