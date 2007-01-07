#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10267);
 script_version ("$Revision: 1.17 $");
 
 name["english"] = "SSH Server type and version";
 script_name(english:name["english"]);
 
 desc["english"] = "This detects the SSH Server's type and version by connecting to the server
and processing the buffer received.
This information gives potential attackers additional information about the
system they are attacking. Versions and Types should be omitted
where possible.

Solution: Apply filtering to disallow access to this port from untrusted hosts

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "SSH Server type and version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports("Services/ssh", 22);
 script_dependencies("find_service.nes");
 exit(0);
}

#
# The script code starts here
#

 port = get_kb_item("Services/ssh");
 if (!port) port = 22;

 key = string("ssh/banner/", port);
 banner = get_kb_item(key);
 
 if(!banner)
 {
 if (get_port_state(port))
 {
  soctcp22 = open_sock_tcp(22);

  if (soctcp22)
  { 
   banner = recv_line(socket:soctcp22, length:1024);
   close(soctcp22);
  }
  }
 }

if("SSH" >< banner){
 
if("OpenSSH" >< banner)set_kb_item(name:"ssh/openssh", value:TRUE);
banner = "Remote SSH version : " + banner;
security_note(port:port, data:banner);
}
 
