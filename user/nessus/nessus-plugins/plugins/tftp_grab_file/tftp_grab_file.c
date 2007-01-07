/*
 * tftp.c
 *
 * This plugins attempts to read the file /etc/passwd or anything
 * else using tftp
 *
 */

#include <includes.h>
/*
 * The following decls are declared in arpa/inet, and thus are 
 * Copyright (c) 1983, 1993 The Regents of the University of California.  
 * All rights reserved.
 */
 
#define RRQ     01                      /* read request */

struct tftp_header {
 unsigned short  th_opcode;              /* packet type */
        union {
                unsigned short  tu_block;       /* block # */
                unsigned short  tu_code;        /* error code */
                char    tu_stuff[1];    /* request packet stuff */
        } th_u;
        char    th_data[1];             /* data or error string */
 };
#define th_block        th_u.tu_block
#define th_code         th_u.tu_code
#define th_stuff        th_u.tu_stuff
#define th_msg          th_data
/**** Now, my stuff */


#define NAME "TFTP get file"
#define DESC "\
The TFTP (Trivial File Transfer Protocol) allows\n\
remote users to read files without having to log in.\n\
This may be a big security flaw, especially if tftpd\n\
(the TFTP server) is not well configured by the\n\
admin of the remote host.\n\
Solution : disable it\n\
Risk factor : High"

#define FR_DESC "\
Le TFTP (Trivial File Transfer Protocol) permet\n\
à un utilisateur distant de lire un fichier sans\n\
avoir a s'authentifier.\n\
Si un serveur tftp tourne et n'est pas bien configuré,\n\
alors sa présence est un risque pour la sécurité de\n\
votre machine.\n\n\
Solution : désactivez-le\n\
Facteur de risque : Elevé"

#define COPYRIGHT "no copyright"
#define SUMM "Attempts to grab a file through tftp"


PlugExport int plugin_init(struct arglist *desc);
PlugExport int plugin_init(struct arglist *desc)
{
  plug_set_id(desc, 10339);
  plug_set_version(desc, "$Revision: 1.9 $");
  plug_set_cve_id(desc, "CAN-1999-0498");
  plug_set_name(desc, NAME, NULL);
  plug_set_description(desc, FR_DESC, "francais");
  plug_set_description(desc, DESC, NULL);
  plug_set_summary(desc, SUMM, NULL);
  plug_set_copyright(desc, COPYRIGHT, NULL);
  plug_set_category(desc, ACT_ATTACK);
  plug_set_family(desc, "Accès aux fichiers distants", "francais");
  plug_set_family(desc, "Remote file access", NULL);
  return(0);
}


PlugExport int plugin_run(struct arglist * env)
{
 int soc;
 struct sockaddr_in addr;
 struct in_addr *p = plug_get_host_ip(env);
 struct tftp_header  * packet;
 char * p_packet;
 char * test_file = get_preference(env, "test_file");
 char * file = NULL;
 int b;
 fd_set read_set;
 char * report;
 int flaw = 0;
 int len = sizeof(struct sockaddr_in);
 struct timeval timeout = {5,0};
 char * asc_to = get_preference(env, "checks_read_timeout");
 
 
 if(asc_to != NULL)
 {
  int x= atoi(asc_to);
  if(x > 0 && x < 255)
   timeout.tv_sec = x;
 }
 
 if( test_file == NULL )
 	test_file = estrdup("/etc/passwd");
	
 p_packet = emalloc(512 + strlen(test_file));
 
 packet = (struct tftp_header *)p_packet;
 
 packet->th_opcode=htons(RRQ);
 sprintf(packet->th_stuff, test_file);
 sprintf(packet->th_stuff+strlen(test_file)+1,"octet");
 

 soc = socket(AF_INET, SOCK_DGRAM, 0);
 set_socket_source_addr(soc, 0);
 addr.sin_family = AF_INET;
 addr.sin_addr = *p;
 addr.sin_port = htons(69);
 connect(soc, (struct sockaddr*)&addr, len);
 b = send(soc, packet, 22, 0);
 
 addr.sin_addr = *p;
 addr.sin_port = 0;
 b=512;
 while(b==512)
 {
 unsigned short block;
 addr.sin_addr = *p;
 addr.sin_port = 0;
 bzero(packet, 512);
 FD_ZERO(&read_set);
 FD_SET(soc, &read_set);
 select(soc+1, &read_set, NULL, NULL, &timeout);
 if(!FD_ISSET(soc, &read_set))break;
 b = recv(soc,packet, 512, 0);
 if(b < sizeof(struct tftp_header))exit(0);
 if(ntohs(packet->th_opcode)==3)
 {
  /* We receive some data : there is a flaw */
  char tmp[512];
  char * tmp2;
  flaw++;
  snprintf(tmp, sizeof(tmp), "%s", packet->th_msg);
  if( file == NULL )
  	tmp2 = emalloc(strlen(tmp)+1);
  else 
  	tmp2 = emalloc(strlen(file)+strlen(tmp)+1);
  
  if( file == NULL )
  	strncpy(tmp2, tmp, strlen(tmp));
  else snprintf(tmp2, strlen(file)+strlen(tmp)+1, "%s%s", file, tmp);
  
  if(file != NULL )
  	efree(&file);
  file = emalloc( strlen(tmp2) + 1 );
  strncpy(file, tmp2, strlen(tmp2));
  efree(&tmp2);
 }
 else break;
 block = ntohs(packet->th_block);
 bzero(packet, 512);
 packet->th_opcode = htons(04);
 packet->th_block = htons(block);
 sendto(soc, packet, 4, 0, (struct sockaddr *)&addr, len);
 }
 
 if(flaw)
 {
 report = emalloc(255+strlen(file)+strlen(test_file));
 sprintf(report, "It was possible to retrieve the file %s\n\
through tftp. Here is what we could grab : \n%s\n\n\
Solution : disable the tftp daemon, or if you really need it\n\
run it in a chrooted environment", test_file, file);
 efree(&file);
 plug_set_key(env, "tftp/get_file", ARG_INT, (void*)1);
 post_hole_udp(env, 69, report);
 }
 return(0);
}
 
 
