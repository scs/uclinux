#include "hydra-mod.h"

extern char *HYDRA_EXIT;

char *buf;

int start_pop3(int s,int port, unsigned char options,char *miscptr,FILE *fp) {
    char *empty = "\"\"";
    char *login, *pass, buffer[300];

    if (strlen(login = hydra_get_next_login()) == 0) login = empty;
    if (strlen(pass = hydra_get_next_password()) == 0) pass = empty;

    while(hydra_data_ready(s) > 0) {
        if ((buf = hydra_receive_line(s)) == NULL) return(1);
        free(buf);
    }

    sprintf(buffer, "USER %.250s\r\n", login);
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
        return 1;
    }
    if ((buf = hydra_receive_line(s)) == NULL) return(1);
    if (buf[0] != '+') {
        fprintf(stderr,"Error: POP3 protocol error or service shutdown: %s\n", buf);
        free(buf);
        return(3);
    }
    free(buf);

    sprintf(buffer, "PASS %.250s\r\n", pass);
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
        return 1;
    }
    if ((buf = hydra_receive_line(s)) == NULL) return(1);
    if (buf[0] == '+') {
        hydra_report_found(port, "pop3", fp);
        hydra_completed_pair_found();
        free(buf);
        if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
            return 3;
        return 1;
    }
    free(buf);
    hydra_completed_pair();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;

    return 2;
}

void service_pop3(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port) {
    int run = 1, next_run, sock = -1;
    int myport = PORT_POP3, mysslport = PORT_POP3_SSL;

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
			port = myport;
                    }
                    if (sock < 0) {
                        fprintf(stderr, "Error: Child with pid %d terminating, can not connect\n", (int)getpid());
                        hydra_child_exit();
                    }
                    buf = hydra_receive_line(sock);
                    if (buf == NULL || buf[0] != '+') { /* check the first line */
                        fprintf(stderr,"Error: Not an POP3 protocol or service shutdown: %s\n", buf);
                        hydra_child_exit();
                        exit(-1);
                    }
                    free(buf);
                    next_run = 2;
                    break;
            case 2: /* run the cracking function */
                    next_run = start_pop3(sock, port, options, miscptr, fp);
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
