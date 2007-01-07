#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10753);
 script_version ("$Revision: 1.9 $");

 name["english"] = "AOLserver Default Password";
 script_name(english:name["english"]);

 desc["english"] = "
The remote web server is running AOL web server (AOLserver) with 
the default username and password set. An attacker may use this 
to gain control of the remote web server.

Solution: Change the default username and password on your web server.

Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "AOLserver Default Password";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/www");
if (!port) port = 8000;

if(get_port_state(port))
 {
  soc = http_open_socket(port);
  if (soc)
  {
    req = string("GET /nstelemetry.adp HTTP/1.0\r\nAuthorization: Basic bnNhZG1pbjp4\r\n\r\n");
    send(socket:soc, data:req);
    buf = http_recv(socket:soc);
    http_close_socket(soc);
    if ((ereg(string:buf, pattern:"HTTP/[0-9]\.[0-9] 200 ")) && 
        ("AOLserver Telemetry" >< buf))
    {
     security_hole(port);
    }
  }
 }

