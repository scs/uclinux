#
# Copyright (C)2000 by Noam Rathaus <noamr@securiteam.com>, Beyond Security Ltd.
#
# Modifications by rd :
#
#	- comment slightly changed
#	- added a solution
#	- risk gravity : medium -> low
#	- french translation
#	- script_id
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10344);
 script_version ("$Revision: 1.9 $"); 
 
 name["english"] = "Detect the presence of Napster";
 name["francais"] = "Detection de la présence de Napster";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
Napster is running on a remote computer. 
Napster is used to share MP3 across the network, and can 
be misused (by modifying the three first bytes of a target 
file) to transfer any file off a remote site.

Solution : filter this port if you do not want your network
           users to exchange MP3 files or if you fear
	   that Napster may be used to transfer any non-mp3 file
	   
Risk factor : Low";

 desc["francais"] = "
Napster tourne sur ce système.
Napster est utilisé pour transférer des MP3 
à travers le réseau, et peut etre utilisé de 
manière détournée (en modifiant les trois premiers
octets du fichier visé) pour transférer des fichiers
hors d'un site distant.

Solution : filtrez ce port si vous ne souhaitez pas
           que les utilisateurs de votre réseau n'échangent
	   des fichiers MP3 ou si vous craignez que napster
	   ne soit utilisé pour transferer des fichiers non-mp3
	   
Facteur de risque : Faible";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Detect the presence of Napster";
 summary["francais"] = "Detecte la présence de Napster";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Beyond Security");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_require_ports("Services/napster", 6699);
 script_dependencies("find_service.nes");
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");

 uk = 0;
 port = get_kb_item("Services/napster");
 if (!port) {
 	port = 6699;
	uk = 1;
	}
 if (get_port_state(port))
 {
  soctcp6699 = open_sock_tcp(port);
  if (soctcp6699)
  {
   resultrecv = recv(socket:soctcp6699, length:50);
   if ("1" >< resultrecv)
   {
    data = string("GET\r\n");
    resultsend = send(socket:soctcp6699, data:data);
    resultrecv = recv(socket:soctcp6699, length:50);
    if (!resultrecv)
    {
     data = string("GET /\r\n");
     resultsend = send(socket:soctcp6699, data:data);
     resultrecv = recv(socket:soctcp6699, length:150);

     if ("FILE NOT SHARED" >< resultrecv)
     {
      security_warning(port:port);
      if(uk)register_service(proto:"napster", port:6699);
     }
    }
   }
   close(soctcp6699);
  }
 }
