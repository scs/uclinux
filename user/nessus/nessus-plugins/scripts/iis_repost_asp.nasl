#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10372);
 script_version ("$Revision: 1.11 $");

 name["english"] = "/scripts/repost.asp";
 name["francais"] = "/script/repost.asp";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The file /scripts/repost.asp is present.

This file allows users to upload files to the /users directory if it has not 
been configured properly.

Solution : Create /users and make sure that the anonymous internet account is
only given read access to it.
See also : http://online.securityfocus.com/archive/82/84565
Risk factor : Serious";


 desc["francais"] = "
Le fichier /scripts/repost.asp est présent.

Ce fichier permet à n'importe qui d'uploader
des fichiers dans /users.


Solution : créez /users et assurez-vous que le compte
	   internet anonyme n'y a accès qu'en lecture seule
Facteur de risque : Sérieux";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Determines whether /scripts/repost.asp is present";
 summary["francais"] = "Determines si /scripts/repost.asp est présent";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

function test_cgi(port, cgi, output)
{
 req = http_get(item:cgi, port:port);
 soc = http_open_socket(port);
 if(!soc)return(0);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 if(output >< r)
  {
  	security_hole(port);
	exit(0);
  }
 return(0);
}
 
 


port = get_kb_item("Services/www");
if(!port)port = 80;
if(get_port_state(port))
{
  test_cgi(port:port, 
 	  cgi:"/scripts/repost.asp",
	  output:"Here is your upload status");	  
}
	  
