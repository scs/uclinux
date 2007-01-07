#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10281);
 script_version ("$Revision: 1.18 $");

 name["english"] = "Detect Server type and version via Telnet";
 script_name(english:name["english"]);
 
 desc["english"] = "This detects the Server's type and version by connecting to the server and
processing the buffer received.
This information gives potential attackers additional information about the
system they are attacking. Versions and Types should be omitted
where possible.

Solution: Change the login banner to something generic.

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detect Server type and version via Telnet";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencies("find_service.nes");
 script_require_ports("Services/telnet", 23);
 exit(0);
}

#
# The script code starts here
#
include("telnet_func.inc");

port = get_kb_item("Services/telnet");
if(!port)port = 23;
if (get_port_state(port))
{
  banner = get_telnet_banner(port: port);
  if(strlen(banner))
  {
   data = string("Remote telnet banner :\n");
   if(banner)data = data + banner;
   l = strlen(banner);
   security_note(port:port, data:data);
  }
}
