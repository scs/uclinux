#
# Copyright 2001 by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10826);
 script_version("$Revision: 1.4 $");
 name["english"] = "Unprotected Netware Management Portal";
 script_name(english:name["english"]);

 desc["english"] = "
 
The Netware Management Portal software is running
on this machine. The Portal allows anyone to view
the current server configuration and locate other
Portal servers on the network. It is possible to
browse the server's filesystem by requesting the
volume in the URL. However, a valid user account
is needed to do so.


Solution: Disable this service if it is not in use or
block connections to this server on TCP ports 
8008 and 8009.

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Unprotected Netware Management Portal";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 Digital Defense Inc.");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 8008);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");


# ssl version sometimes on port 8009
port = get_kb_item("Services/www");
if (!port) port = 8008;

if(get_port_state(port))
 {
  soc = http_open_socket(port);
  if (soc)
  {
    req = http_get(item:"/", port:port);
    send(socket:soc, data:req);
    buf = http_recv(socket:soc);
    http_close_socket(soc);
    if ("NetWare Server" >< buf)
    {
     security_hole(port);
    }
  }
 }
