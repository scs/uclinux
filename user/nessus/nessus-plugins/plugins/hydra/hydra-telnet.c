#include "hydra-mod.h"
#include <arpa/telnet.h>

extern char *HYDRA_EXIT;
char *buf;
int no_line_mode;

// added extra null byte sending via "+ 1" below ... should work!

int start_telnet(int s,int port, unsigned char options,char *miscptr,FILE *fp) {
    char *empty = "";
    char *login, *pass, buffer[300];
    int i = 0;

    no_line_mode = 0; // hmmm seems to work anyway

    if (strlen(login = hydra_get_next_login()) == 0) login = empty;
    if (strlen(pass = hydra_get_next_password()) == 0) pass = empty;

    sprintf(buffer, "%.250s\r", login);
    if (no_line_mode) {
        for (i = 0; i < strlen(buffer) + 1; i++) {
            send(s, &buffer[i], 1, 0);
            usleep(2000);
        }
    } else {
        if (hydra_send(s, buffer, strlen(buffer) + 1, 0) < 0) {
            return 1;
        }
    }

    do {
        if ((buf = hydra_receive_line(s)) == NULL)
	    return 1;
        if (index(buf, '/') != NULL || index(buf, '>') != NULL || index(buf, '%') != NULL || index(buf, '$') != NULL || index(buf, '#') != NULL || index(buf, '%') != NULL) {
            hydra_report_found(port, "telnet", fp);
            hydra_completed_pair_found();
            if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
                return 3;
            free(buf);
            return 1;
        }
        (void) make_to_lower(buf);
        if (strstr(buf, "asswor") != NULL || strstr(buf, "asscode") != NULL || strstr(buf, "ennwort") != NULL) i = 1;
        if (i == 0 && ((strstr(buf, "login:") != NULL && strstr(buf, "last login") == NULL) || strstr(buf, "sername:") != NULL)) {
            free(buf);
            hydra_completed_pair();
            if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
               return 3;
            return 2;
        }
        free(buf);
    } while (i == 0);

    sprintf(buffer, "%.250s\r", pass);
    if (no_line_mode) {
        for (i = 0; i < strlen(buffer) + 1; i++) {
            send(s, &buffer[i], 1, 0);
            usleep(5000);
        }
    } else {
        if (hydra_send(s, buffer, strlen(buffer) + 1, 0) < 0) {
            return 1;
        }
    }

    while ((buf = hydra_receive_line(s)) != NULL && make_to_lower(buf) && 
           (strstr(buf, "login:") == NULL || strstr(buf, "last login:") != NULL) && strstr(buf, "sername:") == NULL) {
        if (index(buf, '/') != NULL || index(buf, '>') != NULL || index(buf, '%') != NULL || index(buf, '$') != NULL || index(buf, '#') != NULL || index(buf, '%') != NULL) {
            hydra_report_found(port, "telnet", fp);
            hydra_completed_pair_found();
            free(buf);
            if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
                return 3;
            return 1;
        }
        free(buf);
    }
    hydra_completed_pair();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
    return 2;
}

void service_telnet(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port) {
    int run = 1, next_run, sock = -1;
    int myport = PORT_TELNET, mysslport = PORT_TELNET_SSL;

    hydra_register_socket(sp);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return;
    while(1) {
        int first;
        int old_waittime = waittime;
        switch(run) {
            case 1: /* connect and service init function */
                    if (sock >= 0) sock = hydra_disconnect(sock);
                    usleep(300000);
                    no_line_mode = 0;
                    first = 0;
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
                    if ((buf = hydra_receive_line(sock)) == NULL) { /* check the first line */
                        fprintf(stderr,"Error: Not a TELNET protocol or service shutdown: %s\n", buf);
                        hydra_child_exit();
                        exit(-1);
                    }
                    if (strstr(buf, "ogin") != NULL || strstr(buf, "sername:") != NULL) {
                        waittime = 6;
                        if (debug) printf("DEBUG: waittime set to %d\n", waittime);
                    }
                    do {
                        unsigned char *buf2 = buf;
                        while (*buf2 == IAC) {
                            if (first == 0) {
                                if (debug) printf("DEBUG: requested line mode\n");
                                write(sock, "\xff\xfb\x22", 3);
                                first = 1;
                            }
                            if ((buf[1] =='\xfc' || buf[1] == '\xfe') && buf2[2] == '\x22') {
                                no_line_mode = 1;
                                if (debug) printf("DEBUG: TELNETD peer does not like linemode!\n");
                            }
                            if (buf2[1] == WILL || buf2[1] == WONT) {
                                buf2[1] = DONT;
                                write(sock, buf2, 3);
                            } else if (buf2[1] == DO || buf2[1] == DONT) {
                                buf2[1] = WONT;
                                write(sock, buf2, 3);
                            }
                            buf2 = buf2 + 3;
                        }
                        if (buf2 != (unsigned char *) buf) {
                            free(buf);
                            buf = hydra_receive_line(sock);
                        } else {
                            buf[0] = 0;                        
                        }
                        if (buf != NULL && buf[0] != 0 && (unsigned char)buf[0] != IAC) make_to_lower(buf);
                    } while ( buf != NULL && (unsigned char) buf[0] == IAC && strstr(buf, "ogin:") == NULL && strstr(buf, "sername:") == NULL);
                    free(buf);
                    waittime = old_waittime;
                    next_run = 2;
                    break;
            case 2: /* run the cracking function */
                    next_run = start_telnet(sock, port, options, miscptr, fp);
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
