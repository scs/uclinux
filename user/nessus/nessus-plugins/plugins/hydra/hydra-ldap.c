/*
 * Unusually, some words about the LDAP module here
 *
 * Sometimes, you need a DN to authenticate to. If you do not now the DN
 * you have to guess it. To make the module flexible, you can do the following:
 *
 * use either   -l dn-scope   or   -m dn-scope   to define a fix one
 *              -L DN-GUESS-FILE                 to guess password AND dn
 * or none of these, and the module will try to authenticate to an empty
 * dn-scope
 *
 * Have fun, van Hauser / THC
 *
 */

#include "hydra-mod.h"

extern char *HYDRA_EXIT;

char *buf;
int counter;

int start_ldap(int s,int port, unsigned char options,char *miscptr,FILE *fp) {
    char *empty = "";
    char *login = "", *pass, buffer[512];
    int length;

    if (miscptr == NULL) {
        if (strlen(login = hydra_get_next_login()) == 0) login = empty;
    } else
        login = miscptr;
    if (strlen(pass = hydra_get_next_password()) == 0) pass = empty;

    length = 14 + strlen(login) + strlen(pass);

    memset(buffer, 0, sizeof(buffer));
    buffer[0] = 48;
    buffer[1] = length - 2;
    buffer[2] = 2;   buffer[3] = 1;
    buffer[4] = counter % 256;
    buffer[5] = 96;
    buffer[6] = length - 7;
    buffer[7] = 2;   buffer[8] = 1;   buffer[9] = 2; // version 2

    buffer[10] = 4;  buffer[11] = strlen(login); // DN
    memcpy(&buffer[12], login, strlen(login));

    buffer[12 + strlen(login)] = 128; buffer[13 + strlen(login)] = strlen(pass);
    memcpy(&buffer[14 + strlen(login)], pass, strlen(pass)); // PASS

    if (hydra_send(s, buffer, length, 0) < 0)
        return 1;
    if ((buf = hydra_receive_line(s)) == NULL)
        return 1;
    
    // success is: 0a 01 00 - failure is: 0a 01 31
    if ((buf[0] != 0 && buf[9] == 0) || (buf[0] != 32 && buf[9] == 32)) {
        hydra_report_found(port, "ldap", fp);
        hydra_completed_pair_found();
        if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
            return 3;
        return 1;
    }

    if ((buf[0] != 0 && buf[0] != 32) && buf[9] != 49) {
        fprintf(stderr, "Uh, unknown LDAP response, remember, this module is beta!\n");
        fprintf(stderr, "Dump: %.2x %.2x %.2x %.2x  %.2x %.2x %.2x %.2x   %.2x %.2x %.2x %.2x  %.2x %.2x %.2x %.2x\n",
        buf[0],buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7],buf[8],buf[9],buf[10],buf[11],buf[12],buf[13],buf[14],buf[15]);
        return 3;
    }

    hydra_completed_pair();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
    return 2;
}

void service_ldap(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port) {
    int run = 1, next_run, sock = -1;
    int myport = PORT_LDAP, mysslport = PORT_LDAP_SSL;

    hydra_register_socket(sp);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return;
    while(1) {
        switch(run) {
            case 1: /* connect and service init function */
                    if (sock >= 0)
                        sock = hydra_disconnect(sock);
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
                    counter = 1;
                    next_run = 2;
                    break;
            case 2: /* run the cracking function */
                    next_run = start_ldap(sock, port, options, miscptr, fp);
                    counter++;
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

