/*
*
*  A2DPD - Bluetooth A2DP daemon for Linux
*
*  Copyright (C) 2006  Frédéric DALLEAU <frederic.dalleau@palmsource.com>
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include "a2dp_ipc.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEFAULTIP    "127.0.0.1"
#define DEFAULTPORT  21453
#define BROADCASTIP  "127.0.0.255"

void close_socket(int sockfd)
{
        if(sockfd>0)
        {
        	shutdown(sockfd, SHUT_RDWR);
        	close(sockfd);
        }
}

int make_udp_socket()
{
        int sockfd = socket(PF_INET, SOCK_DGRAM, 0);
        if(sockfd>0)
        {
                int broadcast=1;
                if(setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) == 0)
                {
                        struct sockaddr_in peer_addr;
                        peer_addr.sin_family = AF_INET;
                        peer_addr.sin_port = htons(DEFAULTPORT);
                        peer_addr.sin_addr.s_addr = inet_addr(BROADCASTIP);
                        // Connect on a datagram socket simulate recvfrom with the address specified
                        bind(sockfd, (struct sockaddr *)&peer_addr, sizeof(peer_addr));
                        if(connect(sockfd, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) == 0)
                        {
                        }
                        else
                        {
                                close(sockfd);
                                sockfd=-1;
                        }
               }
               else
               {
                       close(sockfd);
                       sockfd=-1;
               }
        }
        return sockfd;
}

int make_client_socket()
{
        int sockfd = socket(PF_INET, SOCK_STREAM, 0);
        if(sockfd>0)
        {
                struct sockaddr_in peer_addr;
                peer_addr.sin_family = AF_INET;
                peer_addr.sin_port = htons(DEFAULTPORT);
                peer_addr.sin_addr.s_addr = inet_addr(DEFAULTIP);
                connect(sockfd, (struct sockaddr*)&peer_addr, sizeof(peer_addr));
        }
        return sockfd;
}

int make_server_socket()
{
        int sockfd = socket(PF_INET, SOCK_STREAM, 0);
        struct sockaddr_in my_addr;
        memset(&my_addr, 0, sizeof(my_addr));
        my_addr.sin_family = AF_INET;
        my_addr.sin_port = htons(DEFAULTPORT);
        my_addr.sin_addr.s_addr = INADDR_ANY;

        if(sockfd>0)
        {
        	int on = 1;
        	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
                if(bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr))==0)
                {
                        if(listen(sockfd, 0)==0)
                        {
                                // No error
                        }
                        else
                        {
                                close(sockfd);
                                sockfd = -3;
                        }
                }
                else
                {
                        close(sockfd);
                        sockfd = -2;
                }
        }

        return sockfd;
}

int accept_socket(int sockfd)
{
        // Block until connections
        struct sockaddr_in peer_addr;
        unsigned int sin_size = sizeof(peer_addr);
        int new_fd = accept(sockfd, (struct sockaddr *)&peer_addr, &sin_size);
        return new_fd;
}

void setup_socket(int sockfd)
{
        // Timeouts
        struct timeval t = { 1, 0 };
        setsockopt( sockfd, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof(t));
        setsockopt( sockfd, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));
}


int send_socket(int sockfd, void* buffer, int size)
{
        int result = -1;
        int ioffset = 0;
        while(sockfd>0 && ioffset<size)
        {
                result=send(sockfd, ((char*)buffer)+ioffset, size-ioffset, MSG_NOSIGNAL);
                if(result>0)
                {
                        ioffset += result;
                }
                else
                {
                        break;
                }
        }
        return result;

}

int recv_socket(int sockfd, void* buffer, int size)
{
        int received = 0;
        while(buffer && received<size)
        {
                int result = recv(sockfd, buffer+received, size-received, MSG_NOSIGNAL);
                if(result>0)
                {
                        received += result;
                }
                else
                {
                        received=result;
                        break;
                }
        }
        return received;
}

//
// Utility fonctions
//
void async_run_process(char* cmd)
{
        char command[256];
        char* argv[2];
        int i;
        strncpy(command, cmd, sizeof(command));
        command[sizeof(command)-1]=0;
        argv[0] = strchr(command, ' ');
        if(argv[0]) { *argv[0]=0; argv[0]++; }

        if(cmd && cmd[0])
        {
#ifdef __uClinux__
                switch(vfork())
#else
                switch(fork())
#endif
                {
                        case 0:
                                // Children process
                                // Replace children with new process
                                i = execlp(command, command, argv[0], NULL);
                                printf("execlp failed %s=%d (errno=%d:%s)\n", cmd, i, errno, strerror(errno));
                                break;
                        case -1:
                                // failed
                                printf("Fork %s failed\n", cmd);
                                break;
                        default:
                                printf("Forked %s\n", cmd);
                                // Parent, nothing to do
                                break;
                }
        }
}

void get_config_filename(char* filename, int buffersize)
{
        sprintf(filename, "%s/%s", getenv("HOME"), ".a2dprc");
}

void read_config_string(char* filename, char* section, char* key, char* returnbuffer, int buffersize, char* defvalue)
{
        int found=0, error=0;
        FILE* hFile = fopen(filename, "rt");
	returnbuffer[0] = 0;

        if(hFile)
        {
                // search section
                while(!error && !found && !feof(hFile))
                {
                        char buffer[256], szsection[256];
                        if(fgets(buffer, sizeof(buffer), hFile) == NULL)
                        {
                                error=1;
                                break;
                        }

                        if(sscanf(buffer, "[%s]", szsection)==1)
                        {
                                szsection[strlen(szsection)-1]=0;
                                // Found section
                                if(!strcasecmp(section, szsection))
                                {
                                        // key search loop
                                        while(!error && !found && !feof(hFile))
                                        {
                                                char szkey[256], szvalue[256];
                                                if(fgets(buffer, sizeof(buffer), hFile) == NULL)
                                                {
                                                        error=1;
                                                        break;
                                                }
                                                // Another section name will exit the key search loop
                                                if(sscanf(buffer, "[%s]", szsection)==1)
                                                {
                                                        break;
                                                }
                                                // A key name
                                                if(sscanf(buffer, "%[^=]=%[^\n]", szkey, szvalue)>1)
                                                {
                                                        // Found key
                                                        if(!strcasecmp(key, szkey))
                                                        {
                                                                strncpy(returnbuffer, szvalue, buffersize);
                                                                returnbuffer[buffersize-1]=0;
                                                                found = 1;
                                                        }
                                                }
                                        }
                                }
                        }
                }
                fclose(hFile);
        }

        // Put default value
        if(!found)
        {
                strncpy(returnbuffer, defvalue, buffersize);
                returnbuffer[buffersize-1]=0;
        }
        //syslog(LOG_INFO, "%s [%s] '%s'='%s'", __FUNCTION__, section, key, returnbuffer);
}

int read_config_int(char* filename, char* section, char* key, int defvalue)
{
        char def[32];
        char result[512];
        sprintf(def, "%d", defvalue);
        read_config_string(filename, section, key, result, sizeof(result), def);
        return (atoi(result));
}
