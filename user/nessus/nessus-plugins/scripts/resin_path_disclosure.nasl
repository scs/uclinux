#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# GPL
#
# Source:
# From:"Peter_Gründl" <pgrundl@kpmg.dk>
# To:"bugtraq" <bugtraq@securityfocus.com>
# Subject: KPMG-2002033: Resin DOS device path disclosure
# Date: Wed, 17 Jul 2002 11:33:59 +0200

desc1 = "
Resin will reveal the physical path of the webroot 
when asked for a special DOS device, e.g. lpt9.xtp

An attacker may use this flaw to gain further knowledge
about the remote filesystem layout.
";

sol1 = "
Solution : Upgrade to a later software version.

Risk factor : Low";

if(description)
{
 script_id(11048);
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(5252);
 name["english"] = "Resin DOS device path disclosure";

 script_name(english:name["english"]);
 
 desc["english"] = string(desc1, "\n\n", sol1);

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for Resin path disclosure vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("http_func.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;
if(!get_port_state(port)) exit(0);

# Requesting a DOS device may hang some servers
# According to Peter Gründl's advisory:
# Vulnerable:
# Resin 2.1.1 on Windows 2000 Server
# Resin 2.1.2 on Windows 2000 Server
# <security-protocols@hushmail.com> added Resin 2.1.0
# Not Vulnerable:
# Resin 2.1.s020711 on Windows 2000 Server
# 
# The banner for snapshot 020604 looks like this:
# Server: Resin/2.1.s020604

banner = get_http_banner(port: port);
vulnver=0;

# I suppose that any 2.1 snapshot is all right.
if (egrep(pattern: "^Server: *Resin/2\.((0\..*)|(1\.[0-2]))",
	string: banner, icase: 1) ) vulnver=1;

if (safe_checks())
{
 if (vulnver)
 {
  msg = string(
	desc1, 
	"\n*** Nessus solely relied on the version number of your\n",
	"*** server, so this may be a false alert.\n",
	sol1);
  security_warning(port: port, data: msg);
 }
 exit(0);
}

soc = open_sock_tcp(port);
if(!soc) exit(0);
req = http_get(item:"/aux.xtp", port:port);
send(socket:soc, data:req);
h = http_recv_headers(soc);
r = http_recv_body(socket:soc, headers:h);
close(soc);

badreq=0; vuln=0;
if(egrep(pattern: "^500 ", string: h)) badreq=1;

if (egrep(pattern: "[CDE]:\\(.*\\)*aux.xtp", string:r)) vuln=1;

if (vuln) { security_warning(port); exit(0);}
if (vulnver) {
 msg = string(
	desc1, 
	"\n*** The version number of your server loooks vulnerable\n",
	"*** but the attack did not succeed, so this may be a false alert.\n",
	sol1);
 security_warning(port: port, data: msg);
   
}

