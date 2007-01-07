#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10051);
 script_version ("$Revision: 1.9 $");
 name["english"] = "A CVS pserver is running";
 script_name(english:name["english"]);
 
 desc["english"] = "A CVS (Concurrent Versions System) server is installed, and it is configured
to have its own password file, or use that
of the system. This service starts as a daemon, listening on port
TCP:port.
Knowing that a CVS server is present on the system gives attackers
additional information about the system, such as that this is a
UNIX based system, and maybe a starting point for further attacks.

Solution: Block those ports from outside communication

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "A CVS pserver is running";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports("Services/cvspserver", port);
 script_dependencies("find_service.nes");
 exit(0);
}

#
# The script code starts here
#
port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);

 if (soc)
 {
  senddata = string("\r\n\r\n");
  send(socket:soc, data:senddata);

  recvdata = recv_line(socket:soc, length:1000);
  if ("cvs" >< recvdata)
  {
    security_warning(port);
  }
 }

 close(soc);

}
