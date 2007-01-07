#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added CAN.  Added link to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10968);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "ping.asp";
 script_name(english:name["english"]);
 
 desc["english"] = "The 'ping.asp' CGI is installed. Some versions
allows a cracker to launch a ping flood against your 
machine or another by entering
'127.0.0.1 -l 65000 -t' in the Address field.

Solution : remove it.

Reference : http://online.securityfocus.com/archive/82/275088

Risk factor : Serious";

 desc["francais"] = "Le CGI 'ping.asp' est installé. Certaines 
versions permettent à un pirate de lancer un déni de service (ping flood)
contre votre machine ou une autre en entrant 
'127.0.0.1 -l 65000 -t'
dans le camp Adresse.

Solution : supprimez le.

Risk factor : Serious";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of ping.asp";
 summary["francais"] = "Vérifie la présence de ping.asp";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
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

port = get_kb_item("Services/www");
if (!port) port=80;

if (is_cgi_installed(port:port, item:"ping.asp"))
{
 security_hole(port);
 exit(0);
}

if (is_cgi_installed(port:port, item:"/ping.asp"))
{
 security_hole(port);
 exit(0);
}
