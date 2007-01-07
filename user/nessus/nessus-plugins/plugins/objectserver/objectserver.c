/*
 * XXX untested
 */
 
 
/*   Copyright (c) July 1997       Last Stage of Delirium   */
/*      THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF      */
/*                  Last Stage of Delirium                  */
/*                                                          */
/*   The contents of this file  may be disclosed to third   */
/*   parties, copied and duplicated in any form, in whole   */
/*   or in part, without the prior written consent of LSD.  */

/*   SGI objectserver "account" exploit
*/
/*   Remotely adds account to the IRIX system.
*/
/*   Tested on IRIX 5.2, 5.3, 6.0.1, 6.1 and even 6.2,
*/
/*   which was supposed to be free from this bug (SGI 19960101-01-PX).
*/
/*   The vulnerability "was corrected" on 6.2 systems but
*/
/*   SGI guys fucked up the job and it still can be exploited.
*/
/*   The same considers patched 5.x,6.0.1 and 6.1 systems
*/
/*   where SGI released patches DONT work.
*/
/*   The only difference is that root account creation is blocked.
*/
/*
*/
/*   usage: ob_account ipaddr [-u username] [-i userid] [-p]
*/
/*       -i  specify userid (other than 0)
*/
/*       -u  change the default added username
*/
/*       -p  probe if there's the objectserver running
*/
/*
*/
/*   default account added       : lsd
*/
/*   default password            : m4c10r4!
*/
/*   default user home directory : /tmp/.new
*/
/*   default userid              : 0
*/
/*   Script audit and contributions from Carmichael Security
 *   <http://www.carmichaelsecurity.com>
 *      Erik Anderson <eanders@carmichaelsecurity.com>
 *      Added BugtraqID
 */

#include <includes.h>
#include <sys/uio.h>


struct iovec iov[2];
struct msghdr msg;
char buf1[1024],buf2[1024];
int sck;
unsigned long adr;



unsigned char numer_one[0x10]={
0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,
0x00,0x00,0x00,0x24,0x00,0x00,0x00,0x00
};

unsigned char numer_two[0x24]={
0x21,0x03,0x00,0x43,0x00,0x0a,0x00,0x0a,
0x01,0x01,0x3b,0x01,0x6e,0x00,0x00,0x80,
0x43,0x01,0x01,0x18,0x0b,0x01,0x01,0x3b,
0x01,0x6e,0x01,0x02,0x01,0x03,0x00,0x01,
0x01,0x07,0x01,0x01
};


#ifdef WORDS_BIGENDIAN
unsigned char fake_adrs[0x10]={
0x00,0x02,0x14,0x0f,0xff,0xff,0xff,0xff,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
#else
unsigned char fake_adrs[0x10]={
0x02,0x00,0x14,0x0f,0xff,0xff,0xff,0xff,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
#endif

char *get_sysinfo(int timeout){
    int i=0,len;
    fd_set rd;
    struct timeval tv;
    
    iov[0].iov_base=(char*)numer_one;
    iov[0].iov_len=0x10;
    iov[1].iov_base=(char*)numer_two;
    iov[1].iov_len=0x24;
#if 1 /* PATCH (see below) */   
    memset (&msg, 0, sizeof msg);
#endif
    msg.msg_name=(caddr_t)fake_adrs;
    msg.msg_namelen=0x10;
    msg.msg_iov=iov;
    msg.msg_iovlen=2;
#if 0 /* PATCH solaris has not (aways) these entties */   
    msg.msg_control=(void*)0;
    msg.msg_controllen=0;
#endif
    sendmsg(sck,&msg,0);
    

    iov[0].iov_base=buf1;
    iov[1].iov_base=buf2;
    iov[1].iov_len=0x200;
    msg.msg_iovlen=2;
    bzero(&tv, sizeof(tv));
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    
    FD_ZERO(&rd);
    FD_SET(sck, &rd);
    if(select(sck+1, &rd, NULL, NULL, &tv))
    {
    len=recvmsg(sck,&msg,0);
    while(i<len-0x16)
        if(!memcmp("\x0a\x01\x01\x3b\x01\x78",&buf2[i],6)){
            return(&buf2[i+6]);
        }else i++;
    }
    return(0);
}

#define NAME "IRIX Objectserver"

#define EN_DESC "\
IRIX object server is installed on this host.\n\
There are various security bugs in the implementation\n\
of this service which can be used by an intruder to\n\
gain a root account rather easily.\n\n\n\
Solution : filter incoming traffic to this port\n\
Risk factor : High"

#define FR_DESC "\
IRIX object server est installé sur ce système.\n\
Il y a plusieurs bugs dans celui-ci qui permettent à\n\
un pirate de passer root facilement.\n\
Solution : filtrez le traffic entrant vers ce port\n\
Facteur de risque: Elevé"

#define COPYRIGHT "Original code by LSD. Modified by Renaud Deraison"

#define EN_SUMM "Checks for the presence of IRIX Object Server"
#define FR_SUMM "Vérifie la présence de IRIX Object server"

#define EN_FAMILY "Gain root remotely"
#define FR_FAMILY "Passer root à distance"

PlugExport int plugin_init(struct arglist *desc);
PlugExport int plugin_init(struct arglist *desc)
{
  plug_set_id(desc, 10384);
  plug_set_version(desc, "$Revision: 1.15 $");
  plug_set_cve_id(desc, "CVE-2000-0245");
  plug_set_bugtraq_id(desc, "1079");

  plug_set_name(desc, NAME, NULL);
  plug_set_description(desc, FR_DESC, "francais");
  plug_set_description(desc, EN_DESC, NULL);
  
  plug_set_summary(desc, FR_SUMM, "francais");
  plug_set_summary(desc, EN_SUMM, NULL);
  
  plug_set_copyright(desc, COPYRIGHT, NULL);
  plug_set_category(desc, ACT_ATTACK);
  plug_set_family(desc, FR_FAMILY, "francais");
  plug_set_family(desc, EN_FAMILY, NULL);
  plug_set_dep(desc, "find_service.nes");
  
  plug_set_timeout(desc, PLUGIN_TIMEOUT/8);
  return(0);
}


int plugin_run(desc)
 struct arglist * desc;
{
    char *sys_info;
    struct in_addr * addr;
    char * asc_to = get_preference(desc, "checks_read_timeout");
    struct arglist * globals = arg_get_value(desc, "globals");
    int timeout = 5;
    
    if(asc_to != NULL)
    {
     int x = atoi(asc_to);
     if(x > 0 && x < 255)
      timeout = x;
    }
    

    sck=socket(AF_INET,SOCK_DGRAM,0);
    set_socket_source_addr(sck, 0);
    addr = plug_get_host_ip(desc);
    adr=addr->s_addr;
    memcpy(&fake_adrs[4],&adr,4);

    if((sys_info=get_sysinfo(timeout))){
        post_hole_udp(desc, 9090, NULL);
    }
    close(sck);
    return(0);
}


