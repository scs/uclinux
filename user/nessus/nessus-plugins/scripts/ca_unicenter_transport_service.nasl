#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10033);
 script_version ("$Revision: 1.8 $");
 
 name["english"] = "CA Unicenter's Transport Service is running";
 script_name(english:name["english"]);
 
 desc["english"] = "CA Unicenter Transport Service uses ports TCP:7001, TCP:7003 and UDP:7004
for communication between its clients and other CA Unicenter servers. Since
the above ports are open, CA Unicenter's Transport service is probably
running, and is open for outside attacks.

Solution: Block those ports from outside communication

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "CA Unicenter's Transport Service is running";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 SecuriTeam");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_require_ports(7001, 7003);
 exit(0);
}

#
# The script code starts here
#

if ((get_port_state(7001)) && (get_port_state(7003)) && (get_udp_port_state(7004)))
{
 soctcp7001 = open_sock_tcp(7001);
 soctcp7003 = open_sock_tcp(7003);
 socudp7004 = open_sock_udp(7004);

 if ((soctcp7001) && (soctcp7003) && (socudp7004))
 {
  send (socket:socudp7004, data:"\r\n");
  result = recv(socket:socudp7004, length:1000);
  if (strlen(result)>0)
  {
   set_kb_item(name:"Windows compatible", value:TRUE);
   security_hole(0);
  }
 }

 close(soctcp7001);
 close(soctcp7003);
 close(socudp7004);
}
