#include "hydra-mod.h"

extern char *HYDRA_EXIT;
char *buf;

char *netbios_name(char *orig) {
    int i, len;
    char *ret = malloc(40);

    memset(ret, 0, 40);
    len = strlen(orig);
    for (i=0;i<16;i++) {
        if (i >= len)
            strcat(ret, "CA");
        else {
            int odiv, omod;

            odiv = (orig[i] / 16) + 'A';
            omod = (orig[i] % 16) + 'A';
            ret[strlen(ret)]=odiv;
            ret[strlen(ret)]=omod;
       }
    }
    return(ret);
}

int smb_init(int s, char *name) {
    char *myname  = netbios_name("HYDRA");
    char *hername = netbios_name(name);
    u_char buf[400]; 
    u_char buf1[] = { 0x81, 0x00, 0x00, 0x44, 0x20 };
    u_char buf2[] = { 0x00, 0x20 };
    u_char buf3[] = { 0x00 };
    u_char prot[] = { 0x00,0x00,
                      0x00, 0x89, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00,
                      0x00, 0x00, 0x00, 0x18, 0x01, 0x20, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x66, 0x00, 0x02, 0x50, 0x43,
                      0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B,
                      0x20, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D,
                      0x20, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x4D, 0x49,
                      0x43, 0x52, 0x4F, 0x53, 0x4F, 0x46, 0x54, 0x20,
                      0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B, 0x53,
                      0x20, 0x31, 0x2E, 0x30, 0x33, 0x00, 0x02, 0x4D,
                      0x49, 0x43, 0x52, 0x4F, 0x53, 0x4F, 0x46, 0x54,
                      0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B,
                      0x53, 0x20, 0x33, 0x2e, 0x30, 0x00, 0x02, 0x4c,
                      0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30,
                      0x00, 0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58,
                      0x30, 0x30, 0x32, 0x00, 0x02, 0x53, 0x61, 0x6d,
                      0x62, 0x61, 0x00 };
    u_char *big;
    int pad = 0;
 
    big = malloc(sizeof(buf1) + strlen(hername) +sizeof(buf2) + strlen(myname)
                 + sizeof(buf3));
    memcpy(big, buf1, sizeof(buf1));
    pad += sizeof(buf1);
    memcpy(big+pad, hername, strlen(hername));
    pad += strlen(hername);
    memcpy(big+pad, buf2, sizeof(buf2));
    pad += sizeof(buf2);
    memcpy(big+pad, myname, strlen(myname));
    pad += strlen(myname);
    memcpy(big+pad, buf3, sizeof(buf3));
    pad += sizeof(buf3);	
 		
    hydra_send(s, big, pad, 0);
 
    free(myname);
    free(hername);
    free(big);
 
    hydra_recv(s, buf, sizeof(buf));
    if (buf[0] != 0x82)
 	return -1;	/* failed */

    hydra_send(s, prot, sizeof(prot), 0);
 
    hydra_recv(s, buf, sizeof(buf)); 
    if (buf[9] == 0)
 	return 0;	/* The remote host is willing to talk to us */
    else
 	return -1;	/* failed */
}

int 
smb_login(int s, char *login, char *password) {
    int len = strlen(login) + strlen(password) + 57;
    int bcc = 2 + strlen(login) + strlen(password);
    int len_hi = len / 256, len_low = len % 256;
    int bcc_hi = bcc / 256, bcc_lo = bcc % 256;
    int pass_len = strlen(password) + 1;
    int pass_len_hi = pass_len / 256, pass_len_lo = pass_len % 256;
 
    u_char req[] = { 0x00,0x00,
     	             0x00, 0x00, 0xFF, 0x53, 0x4D, 0x42, 0x73, 0x00,
 	             0x00, 0x00, 0x00, 0x18, 0x01, 0x20, 0x00, 0x00,
	             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	             0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00,
	             0x00, 0x00, 0x0A, 0xFF, 0x00, 0x00, 0x00, 0x04,
	             0x11, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	             0x00, 0x00};
    u_char *t;
    u_char buf[2048];
    
    
    
    req[2] = len_hi;
    req[3] = len_low;
    req[51] = pass_len_lo;
    req[52] = pass_len_hi;
    req[57] = bcc_lo;
    req[58] = bcc_hi;
  
    t = malloc(len + 4);
    memset(t, 0, len + 4);
  
    memcpy(t, req, sizeof(req));
    memcpy(t+sizeof(req), password, strlen(password)+1);
    memcpy(t+sizeof(req)+strlen(password)+1, login, strlen(login)+1);
  
    hydra_send(s, t, sizeof(req)+strlen(password)+1+strlen(login)+1, 0);
    free(t);
    hydra_recv(s, buf, sizeof(buf));
  
    if ((buf[4] == 0xFF) && !buf[9])
       return 0;
    else
       return -1;
}

int start_smb(int s, int port, unsigned char options, char *miscptr, FILE *fp) {
    char *empty = "";
    char *login, *pass;

    if (strlen(login = hydra_get_next_login()) == 0) login = empty;
    if (strlen(pass = hydra_get_next_password()) == 0) pass = empty;
	
    if(smb_login(s, login, pass) == 0) {
        hydra_report_found(port, "smb", fp);
        hydra_completed_pair_found();
        free(buf);
	hydra_disconnect(s);
        if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
            return 3;
        return 1;
    }
    free(buf);
    hydra_completed_pair();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
    hydra_disconnect(s);
    return 1;
}

void service_smb(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port) {
    int run = 1, next_run, sock = -1;
    int myport = PORT_SMB, mysslport = PORT_SMB_SSL;

    hydra_register_socket(sp);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return;
    for(;;) {
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
		    if(smb_init(sock, "*SMBSERVER") < 0) {
                        fprintf(stderr,"Error: smb_init() failed\n");
                        hydra_child_exit();
                        exit(-1);
                    }
                    free(buf);
                    next_run = 2;
                    break;
            case 2: /* run the cracking function */
                    next_run = start_smb(sock, port, options, miscptr, fp);
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
