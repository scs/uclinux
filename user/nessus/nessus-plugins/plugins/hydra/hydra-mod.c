#include "hydra-mod.h"

#ifdef HYDRA_SSL
 #include <openssl/ssl.h>
 #include <openssl/err.h>
#endif

#define MAX_CONNECT_RETRY 1
#define WAIT_BETWEEN_CONNECT_RETRY 3

int intern_socket, extern_socket;
char pair[260];
char HYDRA_EXIT[5] = "\x00\xff\x00\xff\x00";
char *HYDRA_EMPTY = "\x00\x00\x00\x00";
int fail = 0;
int alarm_went_off = 0;
int use_ssl = 0;

#ifdef HYDRA_SSL
 SSL     *ssl = NULL;
 SSL_CTX *sslContext = NULL;
 RSA     *rsa = NULL;
#endif

// ----------------- alarming functions ----------------

void alarming() {
    fail++;
    alarm_went_off++;
// uh, I think it's not good for performance if we try to reconnect to a timeout system!
//    if (fail > MAX_CONNECT_RETRY) {
        fprintf(stderr, "Process %d: Can not connect [timeout], process exiting\n", (int)getpid());
        if (debug) printf("DEBUG_CONNECT_TIMEOUT\n");
        hydra_child_exit();
//    } else {
//	if (verbose) fprintf(stderr, "Process %d: Can not connect [timeout], retrying (%d of %d retries)\n", (int)getpid(), fail, MAX_CONNECT_RETRY);
//    }
}

void interrupt() {
    if (debug) printf("DEBUG_INTERRUPTED\n");
}

// ----------------- internal functions -----------------

int internal__hydra_connect(unsigned long int host, int port, int protocol, int type) {
    int s, ret = -1;
    struct sockaddr_in target;
    if ((s = socket(PF_INET, protocol, type)) >= 0) {
          target.sin_port=htons(port);
          target.sin_family=AF_INET;
          memcpy(&target.sin_addr.s_addr,&host,4);
          signal(SIGALRM,alarming);
          do {
              if (fail > 0) sleep(WAIT_BETWEEN_CONNECT_RETRY);
              alarm_went_off = 0;
              alarm(waittime);
              ret = connect(s,(struct sockaddr*) &target, sizeof(target));
              alarm(0);
              if (ret < 0 && alarm_went_off == 0) {
                  fail++;
                  if (verbose && fail <= MAX_CONNECT_RETRY) fprintf(stderr, "Process %d: Can not connect [unreachable], retrying (%d of %d retries)\n", (int)getpid(), fail, MAX_CONNECT_RETRY);
              }
          } while (ret < 0 && fail <= MAX_CONNECT_RETRY);
          if (ret < 0 && fail > MAX_CONNECT_RETRY) {
              if (debug) printf("DEBUG_CONNECT_UNREACHABLE\n");
// we wont quit here, thats up to the module to decide what to do
//              fprintf(stderr, "Process %d: Can not connect [unreachable], process exiting\n", (int)getpid());
//              hydra_child_exit();
              extern_socket = -1;
              ret = -1;
              return ret;
          }
          ret = s;
          extern_socket = s;
          if (debug) printf("DEBUG_CONNECT_OK\n");
          fail = 0;
    }
    return ret;
}

#ifdef HYDRA_SSL
RSA *ssl_temp_rsa_cb(SSL *ssl, int export, int keylength) {
    if (rsa == NULL)
        rsa = RSA_generate_key(512, RSA_F4, NULL, NULL);
    return rsa;
}

int internal__hydra_connect_ssl(unsigned long int host, int port, int protocol, int type) {
    int socket, err;

    // XXX is this needed?
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    // context: ssl2 + ssl3 is allowed, whatever the server demands
    if ((sslContext = SSL_CTX_new(SSLv23_method())) == NULL) {
        if (verbose) {
            err = ERR_get_error();
            fprintf(stderr, "SSL: Error allocating context: %s\n", ERR_error_string(err, NULL));
        }
        return -1;
    }

    // set the compatbility mode
    SSL_CTX_set_options(sslContext, SSL_OP_ALL);

    // we set the default verifiers and dont care for the results
    (void) SSL_CTX_set_default_verify_paths(sslContext);
    SSL_CTX_set_tmp_rsa_callback(sslContext, ssl_temp_rsa_cb);
    SSL_CTX_set_verify(sslContext, SSL_VERIFY_NONE, NULL);

    if ((socket = internal__hydra_connect(host, port, protocol, type)) < 0)
        return -1;

    if ((ssl = SSL_new(sslContext)) == NULL){
        if (verbose) {
            err = ERR_get_error();
            fprintf(stderr, "Error preparing an SSL context: %s\n", ERR_error_string(err, NULL));
        }
        return -1;
    }
    SSL_set_fd(ssl, socket);
    if (SSL_connect(ssl) <= 0) {
        printf("ERROR %d\n", SSL_connect(ssl));
        if (verbose) {
            err = ERR_get_error();
            fprintf(stderr, "Could not create an SSL session: %s\n", ERR_error_string(err, NULL));
        }
        return -1;
    }

    if (debug)
        fprintf(stderr, "SSL negotiated cipher: %s\n", SSL_get_cipher(ssl));

    use_ssl = 1;

    return socket;
}
#endif

int internal__hydra_recv(int socket, char *buf, int length) {
#ifdef HYDRA_SSL
    if (use_ssl) {
        return SSL_read(ssl, buf, length);
    } else
#endif
        return recv(socket, buf, length, 0);
}

int internal__hydra_send(int socket, char *buf, int size, int options) {
#ifdef HYDRA_SSL
    if (use_ssl) {
	return SSL_write(ssl, buf, size);
    } else
#endif
        return send(socket, buf, size, options);
}

// ------------------ public functions ------------------

void hydra_child_exit() {
    write(intern_socket, "Q", 1);
    exit(-1);
}

void hydra_register_socket(int s) {
    intern_socket = s;
}

char *hydra_get_next_pair() {
    if (pair[0] == 0) {
        read(intern_socket, pair, sizeof(pair));
        if (memcmp(&HYDRA_EXIT, &pair, sizeof(HYDRA_EXIT)) == 0)
            return HYDRA_EXIT;
        if (pair[0] == 0)
            return HYDRA_EMPTY;
    }
    return pair;
}

char *hydra_get_next_login() {
    if (pair[0] == 0)
        return HYDRA_EMPTY;
    return pair;
}

char *hydra_get_next_password() {
    char *ptr = pair;
    while(*ptr != '\0') ptr++;
    ptr++;
    if (*ptr == 0)
        return HYDRA_EMPTY;
    return ptr;
}

void hydra_completed_pair() {
    pair[0] = 0;
    write(intern_socket, "N", 1);
}

void hydra_completed_pair_found() {
    char *login;
    write(intern_socket, "F", 1);
    login = hydra_get_next_login();
    write(intern_socket, login, strlen(login) + 1);
    pair[0] = 0;
}

void hydra_report_found(int port, char * svc, FILE *fp) {
    fprintf(fp, "[%d][%s] login: %s   password: %s\n",port, svc, hydra_get_next_login(),hydra_get_next_password());
}

int hydra_connect_ssl(unsigned long int host, int port) {
#ifdef HYDRA_SSL
    return (internal__hydra_connect_ssl(host, port, SOCK_STREAM, 6));
#else
    return (internal__hydra_connect(host, port, SOCK_STREAM, 6));
#endif
}

int hydra_connect_tcp(unsigned long int host, int port) {
    return (internal__hydra_connect(host, port, SOCK_STREAM, 6));
}

int hydra_connect_udp(unsigned long int host, int port) {
    return (internal__hydra_connect(host, port, SOCK_DGRAM, 17));
}

int hydra_disconnect(int socket) {
    close(socket);
    if (debug) printf("DEBUG_DISCONNECT\n");
    return -1;
}

int hydra_data_ready_writing_timed(int socket, long sec, long usec) {
    fd_set fds;
    struct timeval tv;

    FD_ZERO(&fds);
    FD_SET(socket, &fds);
    tv.tv_sec = sec;
    tv.tv_usec = usec;

    return(select(socket + 1, &fds, NULL, NULL, &tv));
}

int hydra_data_ready_writing(int socket) {
    return(hydra_data_ready_writing_timed(socket, 30, 0));
}

int hydra_data_ready_timed(int socket, long sec, long usec) {
    fd_set fds;
    struct timeval tv;

    FD_ZERO(&fds);
    FD_SET(socket, &fds);
    tv.tv_sec = sec;
    tv.tv_usec = usec;

    return(select(socket + 1, &fds, NULL, NULL, &tv));
}

int hydra_data_ready(int socket) {
    return(hydra_data_ready_timed(socket, 0, 100));
}

int hydra_recv(int socket, char *buf, int length) {
    int ret;
    ret = internal__hydra_recv(socket, buf, length);
    if (debug) printf("DEBUG_RECV_BEGIN|%s|END\n", buf);
    return ret;
}

char *hydra_receive_line(int socket) {
    char buf[300], *buff;
    int i = 0, j = 0, k;

    buff = malloc(sizeof(buf));
    memset(buff, 0, sizeof(buf));

    i = hydra_data_ready_timed(socket, (long) waittime, 0);
    if (i > 0) {
        if ((i = internal__hydra_recv(socket, buff, sizeof(buf))) < 0) {
            free(buff);
            return NULL;
        }
    }
    if (i <= 0) {
        if (debug) printf("DEBUG_RECV_BEGIN|%s|END\n", buff);
        free(buff);
        return NULL;
    } else {
        for(k = 0; k < i; k++)
            if (buff[k] == 0)
                buff[k] = 32;
    }

    j = 1;
    while(hydra_data_ready(socket) > 0 && j > 0) {
        j = internal__hydra_recv(socket, buf, sizeof(buf));
        if (j > 0)
            for(k = 0; k < j; k++)
                if (buff[k] == 0)
                    buff[k] = 32;
        buff=realloc(buff,i+j);
        memcpy(buff+i,&buf,j);
        i=i+j;
    }

    if (debug) printf("DEBUG_RECV_BEGIN|%s|END\n", buff);
    return buff;
}

int hydra_send(int socket, char *buf, int size, int options) {
    if (debug) {
        char debugbuf[size+1];
        int k;
        for (k = 0; k < size; k++)
            if (buf[k] == 0)
                debugbuf[k] = 32;
            else
                debugbuf[k] = buf[k];
        debugbuf[size] = 0;
        printf("DEBUG_SEND_BEGIN|%s|END\n", debugbuf);
    }
//    if (hydra_data_ready_writing(socket)) < 1) return -1; // XXX maybe needed in the future
    return(internal__hydra_send(socket, buf, size, options));
}

int make_to_lower(char *buf) {
    if (buf == NULL) return 1;
    while (buf[0] != 0) {
        buf[0]=tolower(buf[0]);
        buf++;
    }
    return 1;
}
