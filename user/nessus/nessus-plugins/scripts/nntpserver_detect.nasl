#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10159);
 script_version ("$Revision: 1.11 $");
 name["english"] = "News Server type and version";
 script_name(english:name["english"]);
 
 desc["english"] = "This detects the News Server's type and version by connecting to the server
and processing the buffer received.
This information gives potential attackers additional information about the
system they are attacking. Versions and Types should be omitted
where possible.

Solution: Change the login banner to something generic

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "News Server type and version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/nntp", 119);
 
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/nntp");
if (!port) port = 119;

if (get_port_state(port))
{
 soctcp119 = open_sock_tcp(port);

 if (soctcp119)
 {
  resultrecv = recv_line(socket:soctcp119, length:1024);
  if(!resultrecv)exit(0);
  resultrecv = string("Remote NNTP server version : ", resultrecv);
  security_note(port:port, data:resultrecv);
 }

 close(soctcp119);
}
