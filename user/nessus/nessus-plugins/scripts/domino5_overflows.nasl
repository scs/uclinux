#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#
# 

if(description)
{
 script_id(11338);
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(7038, 7039);
 script_cve_id("CAN-2003-0123", "CAN-2001-1311");

 name["english"] = "Lotus Domino Vulnerabilities";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote Lotus Domino server, according to its version number,
is vulnerable to various buffer overflows affecting it when
it acts as a client (through webretriever) or in LDAP.

An attacker may use these to disable this server or
execute arbitrary commands on the remote host.
	

References :
    http://www.rapid7.com/advisories/R7-0011-info.html
    http://www.rapid7.com/advisories/R7-0012-info.html

Solution : Update to Domino 5.0.12 or 6.0.1
Risk factor : High";	

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of the remote Domino Server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/domino");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");


port = get_kb_item("Services/www");
if(!port)port = 80;

banner = get_http_banner(port:port);
if(!banner)exit(0);


if(egrep(pattern:"^Server: Lotus-Domino/(Release-)?(4\..*|5\.0.?([0-9]|1[0-1])[^0-9])", string:banner))security_hole(port);
