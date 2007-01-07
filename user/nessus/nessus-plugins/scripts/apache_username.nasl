#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10766); 
 script_cve_id("CAN-2001-1013");
 script_bugtraq_id(3335);
 script_version ("$Revision: 1.10 $");

 name["english"] = "Apache UserDir Sensitive Information Disclosure";
 script_name(english:name["english"]);

 desc["english"] = "An information leak occurs on Apache based web servers 
whenever the UserDir module is enabled. The vulnerability allows an external 
attacker to enumerate existing accounts by requesting access to their home 
directory and monitoring the response.


Solution: 
1) Disable this feature by changing 'UserDir public_html' (or whatever) to 
'UserDir  disabled'.

Or

2) Use a RedirectMatch rewrite rule under Apache -- this works even if there 
is no such  entry in the password file, e.g.:
RedirectMatch ^/~(.*)$ http://my-target-webserver.somewhere.org/$1

Or

3) Add into httpd.conf:
ErrorDocument 404 http://localhost/sample.html
ErrorDocument 403 http://localhost/sample.html
(NOTE: You need to use a FQDN inside the URL for it to work properly).

Additional Information:
http://www.securiteam.com/unixfocus/5WP0C1F5FI.html


Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "Apache UserDir Sensitive Information Disclosure";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "Misc.";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/www");
if (!port) port = 80;

if (! get_port_state(port)) exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);


soc = http_open_socket(port);
if (soc)
{
 req = http_head(item:"/~root", port:port);
 send(socket:soc, data:req);
 buf_valid = recv_line(socket:soc, length:1000);
 http_close_socket(soc);
}

soc = http_open_socket(port);
if (soc)
{
 req = http_head(item:"/~anna_foo_fighter", port:port);
 send(socket:soc, data:req);
 buf_invalid = recv_line(socket:soc, length:1000);
 http_close_socket(soc);
}

if (("403 Forbidden" >< buf_valid) && ("404 Not Found" >< buf_invalid))
{
 security_note(port);
}


