#include "hydra-mod.h"

extern char *HYDRA_EXIT;
char *buf;

unsigned char conv64(unsigned char in) {
    if (in < 26) return (in + 'A');
    else if (in >= 26 && in < 52) return (in + 'a' - 26);
    else if (in >= 52 && in < 62) return (in + '0' - 52);
    else if (in == 62) return '+';
    else if (in == 63) return '/';
    else { fprintf(stderr, "Too high for base64: %d\n", in); return 0; }
}

void tobase64(unsigned char *buf, int sz) {
    unsigned char bof[200] = "";
    unsigned char small[3] = { 0, 0, 0};
    unsigned char big[5];
    unsigned char *ptr = buf;
    int i;
    int len = 0;

    if (buf == NULL || buf[0] == '\0') 
    	return;
	
    big[4] = 0;
    
    len = 0;
    for (i = 0; i < strlen(buf) / 3; i++) {
        big[0] = conv64(*ptr >> 2);
        big[1] = conv64(((*ptr & 3) << 4) + (*(ptr+1) >> 4));
        big[2] = conv64(((*(ptr+1) & 15) << 2) + (*(ptr+2) >> 6));
        big[3] = conv64(*(ptr+2) & 63);
       
	len += strlen(big);
	if(len >= sizeof(bof))
		return;
        strcat(bof, big);	
        ptr += 3;
    }
    
    if (*ptr != 0) {
        small[0] = *ptr;
        if (*(ptr+1) != 0)
            small[1] = *(ptr+1);
        ptr = small;
        big[0] = conv64(*ptr >> 2);
        big[1] = conv64(((*ptr & 3) << 4) + (*(ptr+1) >> 4));
        big[2] = conv64(((*(ptr+1) & 15) << 2) + (*(ptr+2) >> 6));
        big[3] = conv64(*(ptr+2) & 63);
        if (big[1] == 'A') big[1] = '=';
        if (big[2] == 'A') big[2] = '=';
        if (big[3] == 'A') big[3] = '=';
        strcat(bof, big);
	len += strlen(big);
    }

    strncpy(buf, bof, sz - 1);
    buf[sz - 1] = '\0';
}

int start_http(int s, int port, unsigned char options,char *miscptr,FILE *fp) {
    char *empty = "";
    char *login, *pass, buffer[300], buffer2[110];
    char *header = "";  // XXX TODO:
    char *ptr;

    if (strlen(login = hydra_get_next_login()) == 0) login = empty;
    if (strlen(pass = hydra_get_next_password()) == 0) pass = empty;

    sprintf(buffer2, "%.50s:%.50s", login, pass);
    tobase64(buffer2, sizeof(buffer2));

    sprintf(buffer, "HEAD %.250s HTTP/1.0\r\nAuthorization: Basic %s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\n%s\r\n",
        miscptr, buffer2, header);

    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
        return 1;
    }

    buf = hydra_receive_line(s);
    while (strstr(buf, "HTTP/1.") == NULL && buf != NULL)
        buf = hydra_receive_line(s);

    if (buf == NULL) {
        return 1;
    }

//    while (hydra_data_ready(s) > 0)
//        recv(s, buffer, sizeof(buf), 0);
////        buf = hydra_receive_line(s);

    ptr = ((char*)index(buf, ' ')) + 1;
    if (*ptr == '2') {
        hydra_report_found(port, "www", fp);
        hydra_completed_pair_found();
    } else {
        if (*ptr != '4')
            printf("Unusual return code: %c for %s:%s\n", (char) *(index(buf, ' ') + 1), login,pass);
        hydra_completed_pair();
    }

    free(buf);

    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
    return 1;

}

void service_http(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port) {
    int run = 1, next_run, sock = -1;
    int myport = PORT_HTTP, mysslport = PORT_HTTP_SSL;

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
                    next_run = start_http(sock, port, options, miscptr, fp);
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
