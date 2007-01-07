#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com> 
#
# See the Nessus Scripts License for details
#
# 2002-06-08 Michel Arboi
# The script did not detect the latest versions of the Kazaa software.
# The session is:
# GET / HTTP/1.0
# 
# HTTP/1.0 404 Not Found
# X-Kazaa-Username: xxxx
# X-Kazaa-Network: KaZaA
# X-Kazaa-IP: 192.168.192.168:1214
# X-Kazaa-SupernodeIP: 10.10.10.10:1214


 desc["english"] = "
The Kazaa / Morpheus HTTP Server is running.
This server is used to provide other clients with a
connection point. However, it also exposes sensitive system files.

Solution: Currently there is no way to limit this exposure.
Filter incoming traffic to this port.

More Information: http://www.securiteam.com/securitynews/5UP0L2K55W.html

Risk factor : Serious";


if(description)
{
 script_id(10751);
 script_version ("$Revision: 1.10 $");
 
 name["english"] = "Kazaa / Morpheus Client Detection";
 script_name(english:name["english"]);
 
 

 script_description(english:desc["english"]);
 
 summary["english"] = "Kazaa / Morpheus Client Detect";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 family["english"] = "Peer-To-Peer File Sharing";
 script_family(english:family["english"]);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 1214);
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:1214);
foreach port (ports)
{
  resultrecv = get_http_banner(port: port);
   # if (egrep(pattern:"^Server: KazaaClient", string:resultrecv))
   if ("X-Kazaa-Username: " >< resultrecv)
   {
    buf = strstr(resultrecv, "X-Kazaa-Username: ");
    buf = buf - "X-Kazaa-Username: ";
    subbuf = strstr(buf, string("\r\n"));
    buf = buf - subbuf;
    username = buf;

    buf = "Remote host reported that the username used is: ";
    buf = buf + username;

    set_kb_item(name:"kazaa/username", value:username);
    report = string(desc["english"], "\n\n", buf);
    security_hole(data:report, port:port);
   }
}
 
