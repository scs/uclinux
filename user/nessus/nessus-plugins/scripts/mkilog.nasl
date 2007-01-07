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
 script_id(10359);
 script_version ("$Revision: 1.12 $");

 name["english"] = "ctss.idc check";
 name["francais"] = "verification de ctss.idc";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The CGI /scripts/tools/ctss.idc is present.

This CGI allows an attacker to view and modify SQL database
contents.

Solution : Delete the file

Reference : http://online.securityfocus.com/archive/101/200779
Reference : http://online.securityfocus.com/archive/101/200615

Risk factor : Serious";


 desc["francais"] = "
Le CGI /scripts/tools/ctss.idc est présent.

Ce CGI permet à n'importe qui de voir des infos
sur vos bases SQL ainsi que de modifiez celles-ci.

Solution : retirez-le
Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /scripts/tools/ctss.idc";
 summary["francais"] = "Vérifie la présence de /scripts/tools/ctss.idce";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "httpver.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}

#
# The script code starts here
#

cgi = "/scripts/tools/ctss.idc";
port = is_cgi_installed(cgi);
if(port)security_hole(port);

