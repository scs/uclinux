#include "hydra-mod.h"

#define COMMAND "/bin/ls /"

extern char *HYDRA_EXIT;
char *buf;

int start_rexec(int s,int port, unsigned char options,char *miscptr,FILE *fp) {
    char *empty = "";
    char *login, *pass, buffer[300] = "", buffer2[100], *bptr = buffer2;
    int ret;

    if (strlen(login = hydra_get_next_login()) == 0) login = empty;
    if (strlen(pass = hydra_get_next_password()) == 0) pass = empty;

    memset(buffer2, 0, sizeof(buffer2));
    bptr++;
    
    strcpy(bptr, login);
    bptr += 1 + strlen(login);

    strcpy(bptr, pass);
    bptr += 1 + strlen(pass);
    
    strcpy(bptr, COMMAND);
    
    if (hydra_send(s, buffer2, 4 + strlen(login) + strlen(pass) + strlen(COMMAND), 0) < 0) {
        return 1;
    }

    ret = hydra_recv(s, buffer, sizeof(buffer));

    if (ret > 0 && buffer[0] == 0) {
        hydra_report_found(port, "rexec", fp);
        hydra_completed_pair_found();
    } else
        hydra_completed_pair();

    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
    return 1;
}

void service_rexec(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port) {
    int run = 1, next_run, sock = -1;
    int myport = PORT_REXEC, mysslport = PORT_REXEC_SSL;

    hydra_register_socket(sp);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return;
    while(1) {
        next_run = 0;
        switch(run) {
            case 1: /* connect and service init function */
                   {
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
                    next_run = 2;
                    break;
                   }
            case 2: /* run the cracking function */
                    next_run = start_rexec(sock, port, options, miscptr, fp);
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
