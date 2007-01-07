#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
# Modified by Paul Johnston for Westpoint Ltd <paul@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10759);
 script_cve_id("CAN-2000-0649");
 script_bugtraq_id(1499);
 script_version ("$Revision: 1.10 $");
 name["english"] = "Private IP address leaked in HTTP headers";
 script_name(english:name["english"]);

 desc["english"] = "
This web server leaks a private IP address through its HTTP headers.

This may expose internal IP addresses that are usually hidden or masked
behind a Network Address Translation (NAT) Firewall or proxy server.

There is a known issue with IIS 4.0 doing this in its default configuration.
  See http://support.microsoft.com/support/kb/articles/Q218/1/80.ASP

See the Bugtraq reference for a full discussion.

Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "Checks for private IP addresses in HTTP headers";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2001 Alert4Web.com, 2003 Westpoint Ltd");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;

#
# Craft our own HTTP/1.0 request for the server banner.
# Note: HTTP/1.1 is rarely useful for detecting this flaw.
#
soc = http_open_socket(port);
if(!soc) exit(0);
send(socket:soc, data:string("GET / HTTP/1.0\r\n\r\n"));
banner = http_recv_headers(soc);
http_close_socket(soc);

#
# Check for private IP addresses in the banner
# Ranges are: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
#
private_ip = eregmatch(pattern:"(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})", string:banner);
if(!isnull(private_ip))
{
  report = "
This web server leaks a private IP address through its HTTP headers : " + private_ip[0] + "

This may expose internal IP addresses that are usually hidden or masked
behind a Network Address Translation (NAT) Firewall or proxy server.

There is a known issue with IIS 4.0 doing this in its default configuration.
  See http://support.microsoft.com/support/kb/articles/Q218/1/80.ASP

See the Bugtraq reference for a full discussion.

Risk factor : Low";
  security_warning(port:port, data:report);
}
