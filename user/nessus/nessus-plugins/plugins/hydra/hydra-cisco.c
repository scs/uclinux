#include "hydra-mod.h"

extern char *HYDRA_EXIT;
char *buf;

int start_cisco(int s, int port, unsigned char options,char *miscptr,FILE *fp) {
    char *empty = "";
    char *pass, buffer[300];

    if (strlen(pass = hydra_get_next_password()) == 0) pass = empty;

// maybe \r\n or \r\000 needed instead of a single \n ?
    sprintf(buffer, "%.250s\r\n", pass);
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
        return 1;
    }
    buf = hydra_receive_line(s);
    if (strstr(buf, "assw") != NULL) {
        hydra_completed_pair();
        free(buf);
        if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
            return 3;
        if (strlen(pass = hydra_get_next_password()) == 0) pass = empty;
        sprintf(buffer, "%.250s\r\n", pass);
        if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
            return 1;
        }
        buf = hydra_receive_line(s);
        if (strstr(buf, "assw") != NULL) {
            hydra_completed_pair();
            free(buf);
            if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
                return 3;
            if (strlen(pass = hydra_get_next_password()) == 0) pass = empty;
            sprintf(buffer, "%.250s\r\n", pass);
            if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
                return 1;
            }
            buf = hydra_receive_line(s);
	}

    }

    if (strstr(buf, "assw") != NULL || strstr(buf, "ad ") != NULL || strstr(buf, "attempt") != NULL || strstr(buf, "fail") != NULL) {
        free(buf);
        hydra_completed_pair();
        if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
            return 3;
        return 1;
    }

    hydra_report_found(port, "cisco", fp);
    hydra_completed_pair_found();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
    free(buf);
    return 1;
}

void service_cisco(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port) {
    int run = 1, failc = 0, retry = 1, next_run, sock = -1;
    int myport = PORT_TELNET, mysslport = PORT_TELNET_SSL;

    hydra_register_socket(sp);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return;
    while(1) {
        next_run = 0;
        switch(run) {
            case 1: /* connect and service init function */
                   {
                    unsigned char *buf2 = malloc(256);
                    int f = 0;
                    if (sock >= 0) sock = hydra_disconnect(sock);
                    usleep(275000);
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
                    do {
                        if (f != 0) free(buf2); else f = 1;
                        if ((buf2 = hydra_receive_line(sock)) == NULL) {
                            if (failc < retry) {
                                next_run = 1;
                                failc++;
			        fprintf(stderr, "Error: Child with pid %d was disconnected - retrying (%d of %d retries)\n", (int)getpid(), failc, retry);
			        sleep(3);
                                break;
                            } else {
			        fprintf(stderr, "Error: Child with pid %d was disconnected - exiting\n", (int)getpid());
			        hydra_child_exit();
			    }
                        }
                    } while ( strstr(buf2, "assw") == NULL);
                    free(buf2);
                    if (next_run != 0) break;
                    failc = 0;
                    next_run = 2;
                    break;
                   }
            case 2: /* run the cracking function */
                    next_run = start_cisco(sock, port, options, miscptr, fp);
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
