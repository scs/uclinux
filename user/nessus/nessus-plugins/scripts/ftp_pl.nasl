#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10467);
 script_version ("$Revision: 1.12 $");
 script_bugtraq_id(1471);
 script_cve_id("CVE-2000-0674");
 name["english"] = "ftp.pl shows the listing of any dir";
 name["francais"] = "ftp.pl montre le contenu de tout répertoire";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote ftp.pl cgi can be used to get the listing
of the content of arbitrary directories, using a simple
request like :

http://target/cgi-bin/ftp/ftp.pl?dir=../../../../../../etc


Solution : disable this CGI as no fix is available at this
time (see http://www.feartech.com/vv/ftp.shtml for details
regarding the availability of a patch)

Risk factor : Medium";

 desc["francais"] = "
Le cgi distant ftp.pl peut etre utilisé pour obtenir
la liste du contenu de n'importe quel répertoire sur
la machine distante, en faisant des requetes simples
telles que :

http://cible/cgi-bin/ftp/ftp.pl?dir=../../../../../../etc

Solution : désactivez ce CGI puisque aucun patch n'est
disponible à ce jour (cf http://www.feartech.com/vv/ftp.shtml
pour plus de détails).
Facteur de risque : Moyen";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/ftp/ftp.pl";
 summary["francais"] = "Vérifie la présence de /cgi-bin/ftp/ftp.pl";
 
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
 req = string(dir, "/ftp/ftp.pl?dir=../../../../../../etc");
 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 if("passwd" >< r)security_hole(port);
}
