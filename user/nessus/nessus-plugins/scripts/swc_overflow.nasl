#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive and Securiteam
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10493);
 script_version ("$Revision: 1.13 $");
 
 name["english"] = "SWC Overflow";
 name["francais"] = "Dépassement de buffer dans SWC";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The CGI 'swc' (Simple Web Counter) is present and vulnerable
to a buffer overflow when issued a too long value to the
'ctr=' argument.

An attacker may use this flaw to gain a shell on this host

Solution : Use another web counter, or patch this one by hand

Reference : http://online.securityfocus.com/archive/1/76818
Reference : http://www.securiteam.com/unixfocus/5FP0O202AE.html

Risk factor : Serious";


 desc["francais"] = "
Le CGI 'swc' (Simple Web Counter) est présent et vulnérable à un
dépassement de buffer lorsqu'une valeur trop longue est donnée
à l'argument 'ctr='.

Un pirate peut utiliser ce problème pour obtenir un shell sur
ce système.

Solution : Utilisez un autre compteur web, ou patchez celui-ci à
la main
Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/swc";
 summary["francais"] = "Vérifie la présence de /cgi-bin/swc";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");


port = get_kb_item("Services/www");
if(!port)port = 80;

if(!get_port_state(port))exit(0);


foreach dir (cgi_dirs())
{
 req = http_get(item:string(dir, "/swc?ctr=", crap(500)),
 	        port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 
 if("Could not open input file" >< r)
 {
   soc = http_open_socket(port);
   req = http_get(item:string(dir, "/swc?ctr=", crap(5000)), port:port);
   send(socket:soc, data:req);
   r = recv_line(socket:soc, length:1024);
   http_close_socket(soc);
   if(ereg(pattern:"HTTP/[0-9]\.[0-9] 500 ", 
	   string:r))security_hole(port);
 }
}
