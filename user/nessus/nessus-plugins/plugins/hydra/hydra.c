/*
 * hydra v2.2 (c) 2001-2002 by van Hauser / THC <vh@reptile.rug.ac.be>
 * http://www.hackerschoice.com
 *
 * Parallized network login hacker. Do only use for legal purposes.
 */

#ifdef NESSUS_PLUGIN
 #include <includes.h>
#endif

#include "hydra.h"

extern void service_telnet(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port);
extern void service_ftp(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port);
extern void service_pop3(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port);
extern void service_imap(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port);
extern void service_ldap(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port);
extern void service_cisco(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port);
extern void service_cisco_enable(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port);
extern void service_vnc(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port);
extern void service_socks5(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port);
extern void service_rexec(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port);
extern void service_nntp(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port);
extern void service_http(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port);
extern void service_icq(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port);
extern void service_pcnfs(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port);
extern void service_smb(unsigned long int ip, int sp, unsigned char options, char *miscptr, FILE *fp, int port);
// ADD NEW SERVICES HERE
#define SERVICES  "telnet ftp pop3 imap  http https smb cisco cisco-enable ldap nntp vnc rexec socks5 icq pcnfs"
// ADD NEW SERVICES HERE

#define MAXBUF    264
#define MAXTASKS  255

#define PROGRAM   "Hydra"
#define VERSION   "v2.2"
#define AUTHOR    "van Hauser / THC"
#define EMAIL     "<vh@reptile.rug.ac.be>"
#define RESSOURCE "http://www.thehackerschoice.com"

#define DEBUG	  0
#define WAITTIME  30
#define TASKS     4

char *prg, *tmp;
extern char HYDRA_EXIT[5];
extern int debug;
extern int verbose;
extern int waittime;
extern int port;
size_t extra;
int killed = 0;

static pid_t pids[MAXTASKS];

void help() {
    printf("hydra");
    exit(-1);
}

void bail(char *text) {
    fprintf(stderr, "Error: %s\n", text);
    exit(-1);
}

void killed_childs(int signo) {
    killed++;
    (void) wait3(NULL, WNOHANG, NULL);
}

void kill_children(int signo) {
    int i;
    for (i = 0; i < MAXTASKS; i++)
    if (pids[i] > 0)
        kill(pids[i], SIGTERM);
    sleep(1);
    if (pids[i] > 0)
        kill(pids[i], SIGKILL);
    exit(0);
}

unsigned long int countlines(FILE *fp) {
    size_t lines = 0, size = 0;
    char *buf = malloc(MAXBUF);
    while (!feof(fp)) {
        if (fgets(buf, MAXBUF, fp) != NULL) {
            if (buf[0] != 0) {
                size += strlen(buf);
                lines++;
            }
        }
    }
    rewind(fp);
    size++;
    extra = size;
    return lines;
}

void fill_mem(char *ptr, FILE *fp) {
    char tmp[MAXBUF + 4] = "";
    while (! feof(fp)) {
        if (fgets(tmp, MAXBUF, fp) != NULL) {
            if (tmp[0] != 0) {
                if (tmp[strlen(tmp)-1] == '\n')
                    tmp[strlen(tmp)-1] = '\0';
                if (tmp[strlen(tmp)-1] == '\r')
                    tmp[strlen(tmp)-1] = '\0';
                memcpy(ptr, tmp, strlen(tmp));
                ptr += strlen(tmp);
                *ptr = '\0';
                ptr++;
            }
        }
    }
    fclose(fp);
}


#ifdef NESSUS_PLUGIN
 int hydra_main(int soc, struct arglist *nessus, int argc, char *argv[]) {
#else
 int hydra_main(int soc, void *nessus, int argc, char *argv[]) {
#endif
    unsigned int tasks = 1, exit_found = 0;
    unsigned int ssl = 0, group = MAXTASKS + 1;
    unsigned char options = 0;
    int try_password_same_as_login = 0, try_null_password = 0;
    char *login = NULL, *loginfile = NULL, *pass = NULL, *passfile = NULL;
    char *colonfile = NULL, *outfile_ptr = NULL;
    char *miscptr = NULL, *server, *service;

    char *login_ptr, *pass_ptr = "", *pass_ptr_save, *csv_ptr;
    FILE *lfp, *pfp, *cfp, *ofp = stdout;
    unsigned int socketpairs[MAXTASKS][2];
    size_t countlogin = 1, sizelogin = 0, countpass = 0, sizepass = 0;
    unsigned long int math2, todo, sent = 0;
    struct hostent *target;
    unsigned long int ip;
    struct in_addr in;
    int i, j;
#ifdef NESSUS_PLUGIN    
    char * svc_kb_name;
    char * asc_port;
#endif  
    
    char empty_login[2] = "";
    prg = argv[0];
    debug = 0;
    verbose = 0;
    waittime = WAITTIME;
    port = 0;
    tasks = TASKS;
    if (argc < 4) help();
    tmp = malloc(MAXBUF);

    while ((i = getopt(argc, argv, "de:vl:fg:L:p:P:o:C:t:m:w:s:S")) >= 0) {
        switch (i) {
            case 'd': debug = 1; verbose++; break;
            case 'e': i = 0;
                      while (i < strlen(optarg)) {
                          switch(optarg[i]) {
                              case 'n': try_null_password = 1; break;
                              case 's': try_password_same_as_login = 1; break;
                              default: fprintf(stderr,"Error: unknown mode %c for option -e, only supporting \"n\" and \"s\"\n", optarg[i]);
                              exit(-1);
                          }
                          i++;
                      }
                      break;
            case 'v': verbose = 1; break;
            case 'l': login = optarg; break;
            case 'L': loginfile = optarg; break;
            case 'p': pass = optarg; break;
            case 'P': passfile = optarg; break;
            case 'f': exit_found = 1; break;
            case 'g': group = atoi(optarg); break;
            case 'o': outfile_ptr = optarg; break;
            case 'C': colonfile = optarg; break;
            case 't': tasks = atoi(optarg); break;
            case 'm': miscptr = optarg; break;
            case 'w': waittime = atoi(optarg); break;
            case 's': port = atoi(optarg); break;
            case 'S':
#ifndef HYDRA_SSL
		      fprintf(stderr, "Sorry, hydra was compiled without SSL support. Install openssl and recompile!\n");
                      ssl = 0; break;
#else 
            	      ssl = 1; break;
#endif
            default: fprintf(stderr,"Error: unknown option -%c\n", i); help();
        }
    }
    if (optind + 2 != argc && optind + 3 != argc) help();
    server = argv[optind];
    service = argv[optind + 1];
    if (optind + 3 == argc) miscptr = argv[optind + 2];
    
    i = 0;
    if (strcmp(service, "telnet") == 0) i = 1;
    if (strcmp(service, "ftp") == 0) i = 1;
    if (strcmp(service, "pop3") == 0) i = 1;
    if (strcmp(service, "imap") == 0) i = 1;
    if (strcmp(service, "rexec") == 0) i = 1;
    if (strcmp(service, "nntp") == 0) i = 1;
    if (strcmp(service, "socks5") == 0) i = 1;
    if (strcmp(service, "icq") == 0) i = 1;
// ADD NEW SERVICES HERE
    if (strcmp(service, "smb") == 0) {
        if (tasks > 1) {
            fprintf(stderr, "Reduced number of tasks to 1 (smb does not like parallel connections)\n");
            tasks = 1;
        }
        i = 1;
    }
    if (strcmp(service, "pcnfs") == 0) {
        i = 1;
        if (port == 0) {
            fprintf(stderr, "Error: You must set the port for pcnfs with -s (run \"rpcinfo -p %s\" and look for the pcnfs v2 UDP port)\n", server);
            exit(-1);
        }
    }
    if (strcmp(service, "cisco") == 0) {
        i = 2;
        login = empty_login;
        if (tasks > 4)
            printf("Warning: you should set the number of parallel task to 4 for cisco services.\n");
    }
    if (strcmp(service, "ldap") == 0) {
        i = 1;
        if ((miscptr != NULL && login != NULL) || (miscptr != NULL && loginfile != NULL) || (login != NULL && loginfile != NULL))
            bail("Error: you may only use one of -l, -L or -m (or none)\n");
        if (login == NULL && loginfile == NULL && miscptr == NULL)
            fprintf(stderr, "Warning: no DN to authenticate to defined, using DN of null (use -m, -l or -L to define DNs)\n");
        if (login == NULL && loginfile == NULL) {
            i = 2;
            login = empty_login;
        }
    }
    if (strcmp(service, "cisco-enable") == 0) {
        i = 2;
        login = empty_login;
        if (miscptr == NULL) {
            bail("Error: You must supply the inial password to logon via the -m option\n");
        }
        if (tasks > 4)
            printf("Warning: you should set the number of parallel task to 4 for cisco enable services.\n");
    }
    if (strcmp(service, "vnc") == 0) {
        i = 2;
        login = empty_login;
        if (tasks > 4)
            printf("Warning: you should set the number of parallel task to 4 for vnc services.\n");
    }
    if (strcmp(service, "www") == 0 || strcmp(service, "http") == 0) {
        i = 1; 
        if (miscptr == NULL) bail("You must supply the web page as an additional option or via -m");
        if (*miscptr != '/') bail("The web page you supplied must start with a \"/\", e.g. \"/protected/login\"");
        strcpy(service, "www");
    }
#ifdef HYDRA_SSL
    if (strcmp(service, "ssl") == 0 || strcmp(service, "https") == 0) {
        i = 1; 
        if (miscptr == NULL) bail("You must supply the web page as an additional option or via -m");
        if (*miscptr != '/') bail("The web page you supplied must start with a \"/\", e.g. \"/protected/login\"");
        ssl = 1;
        strcpy(service, "www");
    }
#endif
// ADD NEW SERVICES HERE
    if (i == 0) bail("Unknown service");

    if (i == 2 && ((login != NULL && strlen(login) > 0) || loginfile != NULL || colonfile != NULL))
        bail("The cisco, cisco-enable and vnc crack modes are only using the -p or -P option, not login (-l, -L) or colon file (-C).\nUse the normal telnet crack mode for cisco using \"Username:\" authentication.\n");
    if (i == 1 && login == NULL && loginfile == NULL && colonfile == NULL)
        bail("I need at least either the -l, -L or -C option to know the login");
    if (colonfile != NULL && ((login != NULL || loginfile != NULL) || (pass != NULL && passfile != NULL)))
        bail("The -C option is standalone, dont use it with -l/L and -p/P !");
    if (try_password_same_as_login == 0 && try_null_password == 0 && pass == NULL && passfile == NULL && colonfile == NULL)
        bail("I need at least the -e, -p or -P option to have some passwords!");
    if (tasks < 1 || tasks > MAXTASKS) {
        fprintf(stderr, "Option -t needs to be a number between 1 and %d", MAXTASKS);
        exit(-1);
    }

    if (loginfile != NULL) {
        if ((lfp = fopen(loginfile, "r")) == NULL)
            bail("File for logins not found!");
        countlogin = countlines(lfp);
        sizelogin = extra;
        if (countlogin == 0)
            bail("File for logins is empty!");
        login_ptr = malloc(sizelogin);
        fill_mem(login_ptr, lfp);
    } else
        login_ptr = login;
    if (passfile != NULL) {
        if ((pfp = fopen(passfile, "r")) == NULL)
            bail("File for passwords not found!");
        countpass = countlines(pfp);
        sizepass = extra;
        if (countpass == 0)
            bail("File for passwords is empty!");
        pass_ptr = malloc(sizepass);
        fill_mem(pass_ptr, pfp);
    } else {
        if (pass != NULL) {
            pass_ptr = pass;
            countpass = 1;
        }
    }
    if (colonfile != NULL) {
        if (try_password_same_as_login + try_null_password > 0)
            bail("Error: the -C option may not be used together with the -e option\n");
        if ((cfp = fopen(colonfile, "r")) == NULL)
            bail("File with login:password information not found!");
        countlogin = countlines(cfp);
        sizelogin = extra;
        if (countlogin == 0)
            bail("File for login:password information is empty!");
        csv_ptr = malloc(sizelogin);
        fill_mem(csv_ptr, cfp);
        countpass = 1;
        pass_ptr = login_ptr = csv_ptr;
        while(*pass_ptr != '\0' && *pass_ptr != ':') pass_ptr++;
        if (*pass_ptr == ':') {
            *pass_ptr = '\0';
            pass_ptr++;
        } else {
            fprintf(stderr, "Invalid line in colonfile: %s\n", login_ptr);
            pass_ptr = HYDRA_EXIT;
        }
    }

    countpass += try_password_same_as_login + try_null_password;
    math2 = countlogin * countpass;
    if (math2 < tasks) {
        tasks = math2;
        fprintf(stderr, "Warning: More tasks defined than login/pass pairs exist. Tasks reduced to %d.\n",tasks);
    }
    todo = math2;

    // set options (bits!)
    options = 0;
    if (ssl)
        options = options | OPTION_SSL;

    printf("%s %s (c) 2002 by %s - use allowed only for legal purposes.\n", PROGRAM, VERSION, AUTHOR);
    printf("%s is starting! [parallel tasks: %d, login tries: %lu (l:%d/p:%d)]\n",PROGRAM,tasks,todo,countlogin,countpass);

    math2 = math2 / tasks;
    if (verbose)
        printf("Approx. login tries per task: %lu (%d tasks)\n",math2,tasks);

    /* resolve target */
    // if ((ip = inet_addr(server)) == -1) { //deprecated
    if (inet_pton(AF_INET, server, &in) <= 0) {
        if ((target = gethostbyname(server)) == NULL) {
	    perror(server);
	    exit(-1);
        }
        memcpy(&ip, target->h_addr, 4);
    } else {
        memcpy(&ip, &in.s_addr, 4);
    }

    if (outfile_ptr != NULL) {
        char datetime[24];
        struct tm *the_time;
        time_t epoch;
        if ((ofp = fopen(outfile_ptr, "a+")) == NULL) {
            bail("Error creating outputfile");
        }
        time(&epoch);
        the_time = localtime(&epoch);
        strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S", the_time);
        fprintf(ofp, "# %s %s run at %s on %s %s ( ", PROGRAM, VERSION, datetime, server, service);
        if (login     != NULL) fprintf(ofp, "-l %s ", login);
        if (pass      != NULL) fprintf(ofp, "-p %s ", pass);
        if (colonfile != NULL) fprintf(ofp, "-C %s ", colonfile);
        if (loginfile != NULL) fprintf(ofp, "-L %s ", loginfile);
        if (passfile  != NULL) fprintf(ofp, "-P %s ", passfile);
        if (try_password_same_as_login) fprintf(ofp, "-e s ");
        if (try_null_password) fprintf(ofp, "-e n ");
        fprintf(ofp, ")\n");
    }

    /* we have to flush all writeable buffered file pointers before forking */
    fflush(stdout);
    fflush(stderr);
    fflush(ofp);
    
#ifdef NESSUS_PLUGIN    
    svc_kb_name = malloc(40 + strlen(service));
    if(strcmp(service, "http") == 0)
      strcpy(svc_kb_name, "Services/www");
    else
      sprintf(svc_kb_name, "Services/%s", service);
    asc_port = plug_get_key(nessus, svc_kb_name);
    if (asc_port)port = atoi(asc_port);
    else if(asc_port == NULL )
    {
     if(strcmp(svc_kb_name, "Services/www") == 0 )
     	port = 80;
     else if(strcmp(svc_kb_name, "Services/telnet") == 0 )
     	port = 23;
     else if(strcmp(svc_kb_name, "Services/ftp") == 0 )
     	port = 21;
     else if(strcmp(svc_kb_name, "Services/pop3") == 0 )
       port = 110;
     else if(strcmp(svc_kb_name, "Services/imap") == 0 )  
       port = 143;
     else if(strcmp(svc_kb_name, "Services/cisco") == 0 )  
      port  = 23;
     else if(strcmp(svc_kb_name, "Services/cisco-enable") == 0 )
      port = 23;
     else if(strcmp(svc_kb_name, "Services/vnc") == 0 )  
      port = 5900;
     else if(strcmp(svc_kb_name, "Services/sock5") == 0 ) 
      port = 1080;
     else if(strcmp(svc_kb_name, "Services/nntp") == 0 )
      port = 119;
     else if(strcmp(svc_kb_name, "Services/icq") == 0 )
      port = 80;
     else if(strcmp(svc_kb_name, "Services/smb") == 0 )
      port = 139;
     else if(strcmp(svc_kb_name, "Services/ldap") == 0 )
      port = 389;
     else if(strcmp(svc_kb_name, "Services/rexec") == 0 ) 
      port = 512;
    }
    free(svc_kb_name);
    
    if(port && host_get_port_state(nessus, port) == 0)
    	return 0;
    if (port && IS_ENCAPS_SSL(plug_get_port_transport(nessus, port)))
		options |= OPTION_SSL;
    if (soc >= 0)
    	ofp = fdopen(soc, "r+");		
#endif

    /* fork attack processes */
    signal(SIGCHLD, killed_childs);
    signal(SIGTERM, kill_children);
    signal(SIGSEGV, kill_children);
    signal(SIGHUP, kill_children);
    for(i = 0; i < tasks; i++) {
        if (socketpair(PF_UNIX, SOCK_STREAM, 0, socketpairs[i]) != 0) {
            perror("socketpair failed");
            socketpairs[i][0] = -1;
        } else {
            if ((pids[i] = fork()) == 0) {
	    	signal(SIGTERM, exit);
                signal(SIGHUP, exit);
    if (strcmp(service, "telnet") == 0) service_telnet(ip, socketpairs[i][1], options, miscptr, ofp, port);
    if (strcmp(service, "ftp") == 0) service_ftp(ip, socketpairs[i][1], options, miscptr, ofp, port);
    if (strcmp(service, "pop3") == 0) service_pop3(ip, socketpairs[i][1], options, miscptr, ofp, port);
    if (strcmp(service, "imap") == 0) service_imap(ip, socketpairs[i][1], options, miscptr, ofp, port);
    if (strcmp(service, "ldap") == 0) service_ldap(ip, socketpairs[i][1], options, miscptr, ofp, port);
    if (strcmp(service, "www") == 0) service_http(ip, socketpairs[i][1], options, miscptr, ofp, port);
    if (strcmp(service, "cisco") == 0) service_cisco(ip, socketpairs[i][1], options, miscptr, ofp, port);
    if (strcmp(service, "cisco-enable") == 0) service_cisco_enable(ip, socketpairs[i][1], options, miscptr, ofp, port);
    if (strcmp(service, "socks5") == 0) service_socks5(ip, socketpairs[i][1], options, miscptr, ofp, port);
    if (strcmp(service, "vnc") == 0) service_vnc(ip, socketpairs[i][1], options, miscptr, ofp, port);
    if (strcmp(service, "rexec") == 0) service_rexec(ip, socketpairs[i][1], options, miscptr, ofp, port);
    if (strcmp(service, "nntp") == 0) service_nntp(ip, socketpairs[i][1], options, miscptr, ofp, port);
    if (strcmp(service, "icq") == 0) service_icq(ip, socketpairs[i][1], options, miscptr, ofp, port);
    if (strcmp(service, "pcnfs") == 0) service_pcnfs(ip, socketpairs[i][1], options, miscptr, ofp, port);
    if (strcmp(service, "smb") == 0) service_smb(ip, socketpairs[i][1], options, miscptr, ofp, port);
// ADD NEW SERVICES HERE
                return 0;
            }
            if (pids[i] > 0) {
                write(socketpairs[i][1], "N", 1);
                fcntl(socketpairs[i][0], F_SETFL, O_NONBLOCK);
            } else {
                perror("Fork for children failed");
                socketpairs[i][0] = -1;
            }
        }
        if ((((i+1) % group) == 0) && ((i+1) != tasks)) sleep(1);
    }

    /* feed the children with login/pass data - be a good mom */
    {
        int a, b, c, done, length;
        char sb[MAXBUF], rc;
        pass_ptr_save = pass_ptr;
        
        for (a = 0; a < countlogin; a++) {
            for (b = 0; b < countpass; b++) {
                done = 0;
                if ((char *) pass_ptr != (char *) &HYDRA_EXIT) {
                    while(! done) {
                        i = 0;
                        for(c = 0; c < tasks; c++) {
                            if (! done && socketpairs[c][0] >= 0) {
                                if (read(socketpairs[c][0], &rc, 1) > 0) {
                                    if (rc == 'F') {
                                        char *cracked_login = malloc(MAXBUF);
                                        if (exit_found) {
                                            sleep(1);
                                            for (i = 0; i < tasks; i++)
                                                if (pids[i] > 0)
                                                    (void) kill(pids[i], SIGTERM);
                                            sleep(1);
                                            fclose(ofp);
                                            printf("%s Finished.\n", PROGRAM);
                                            exit(0);
                                        }
                                        memset(cracked_login, 0, MAXBUF);
                                        read(socketpairs[c][0], cracked_login, MAXBUF);
                                        if (colonfile == NULL) {
                                            if (strcmp(cracked_login, login_ptr) == 0) {
                                                a++;
                                                if (a < countlogin) {
                                                    while (*login_ptr != '\0') login_ptr++;
                                                    login_ptr++;
                                                    pass_ptr = pass_ptr_save;
                                                    sent += countpass - b;
                                                    b = 0;
                                                } else {
                                                    rc = 'X';
                                                    b = countpass;
                                                    sent = todo;
                                                    done = 1;
                                                }
                                                if (verbose)
                                                    printf("The password for \"%s\" was found, skipping to next login (pairs already sent to childrens will still be tried)\n", cracked_login);
                                            }
                                        }
                                    }
                                    if (rc == 'N' || rc == 'F') {
                                        done = 1;
                                        sent++;
                                        memset(&sb, 0, sizeof(sb));
                                        length = strlen(login_ptr) + 1;
                                        strcpy(sb, login_ptr);
                                        if (b < try_password_same_as_login + try_null_password) {
                                            if (try_null_password && b == 0) {
                                                length += 1;
                                            }
                                            if (try_password_same_as_login && ((b == 0 && try_null_password == 0) || (b == 1 && try_null_password))) {
                                                strcpy(sb + length, login_ptr);
                                                length += strlen(login_ptr) + 1;
                                            }
                                        } else {
                                            while (((try_password_same_as_login && strcmp(pass_ptr, login_ptr) == 0)
                                                   ||
                                                  (try_null_password && strlen(pass_ptr) == 0)) && b < countpass) {
                                                if (verbose)
                                                    printf("Detected double with -e n|s option, skipping double password try. %s <-> %s\n", login_ptr, pass_ptr);
                                                pass_ptr += strlen(pass_ptr) + 1;
                                                b++;
                                                sent++;
                                            }
                                            if (b == countpass) {
                                                strcpy(sb + length, "THChydra");
                                                length += 9;
                                                b = countpass - 1;
                                                if (sent > todo)
                                                    sent = todo;
                                            } else {
                                                strcpy(sb + length, pass_ptr);
                                                length += strlen(pass_ptr) + 1;
                                            }
                                        }
                                        if (verbose)
                                            printf("New pair: login \"%s\" - pass \"%s\" \t(%lu of %lu completed)\n", sb, sb + strlen(sb) + 1, sent, todo);
                                        write(socketpairs[c][0], sb, length);
                                        if (debug) printf("Pair sent to process %d\n", pids[c]);
                                    } else {
                                        if (debug) printf("Process %d reported it quit\n",pids[c]);
                                        socketpairs[c][0] = -1;
                                        pids[c] = 0;
                                        i++;
                                        (void) wait3(NULL, WNOHANG, NULL);
                                    }
                                }
                            } else i++;
                        }
                        if (i >= tasks || killed >= tasks) {
                            printf("All childrens are dead.\n");
                            exit(-1);
                        }
                    }
                }
                if (b < countpass && b >= try_password_same_as_login + try_null_password) {
                    while(*pass_ptr != '\0') pass_ptr++;
                    pass_ptr++;
                }
            }
            if (a < countlogin) {
                while(*login_ptr != '\0') login_ptr++;
                login_ptr++;
            }
            if (colonfile == NULL) {
                pass_ptr = pass_ptr_save;
            } else {
                if ((char *) pass_ptr != (char *) &HYDRA_EXIT) {
                    while(*login_ptr != '\0') login_ptr++;
                    login_ptr++;
                }
                pass_ptr = login_ptr;
                while(*pass_ptr != '\0' && *pass_ptr != ':') pass_ptr++;
                if (*pass_ptr == ':') {
                    *pass_ptr = '\0';
                    pass_ptr++;
                } else {
                    if (strlen(login_ptr) > 0) fprintf(stderr, "Invalid line in colonfile: %s\n", login_ptr);
                    pass_ptr = HYDRA_EXIT;
                }
            }
        }

        i = 0;
        j = 0;
        (void) wait3(NULL, WNOHANG, NULL);
        if (verbose) printf("Waiting for children to finnish their jobs ...\n");
        while(i < tasks && j < 5) {
            i = 0;
            for(c = 0; c < tasks; c++) {
                if (socketpairs[c][0] >= 0) {
                    if (read(socketpairs[c][0], &rc, 1) > 0 || j == 4) {
                        i++;
                        (void) write(socketpairs[c][0], HYDRA_EXIT, sizeof(HYDRA_EXIT));
                        socketpairs[c][0] = -1;
                    }
                } else i++;
            }
            if (i < tasks) {
                j++;
                sleep(1);
            }
        }

	i = 0;
	j = 1;
        while (j > 0 && killed < tasks && i <= (WAITTIME + tasks + 6)) {
	    j = 0;
	    (void) wait3(NULL, WNOHANG, NULL);
	    for(c = 0; c < tasks; c++) {
	        if (pids[c] > 0)
	           if (kill(pids[c], 0) >= 0)
	               j++; 
	    }
	    sleep(1);
	    i++;
	    if (debug) printf("tasks: %d   still alive: %d   killed: %d   time: %d of %d\n", tasks, j, killed, i, WAITTIME + tasks + 6);
        }
    }

    for(i = 0; i < tasks; i++)
        if (pids[i] > 0)
           kill(pids[i], SIGTERM);

    /* yeah we did it */
    printf("%s finished.\n", PROGRAM);

    fclose(ofp);

    return 0;
}


#ifndef NESSUS_PLUGIN
int main(int argc, char * argv[]) {
    return hydra_main(-1, NULL, argc, argv);
}
#endif
