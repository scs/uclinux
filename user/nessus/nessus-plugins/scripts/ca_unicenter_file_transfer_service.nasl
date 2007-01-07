#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10032);
 script_version ("$Revision: 1.9 $");
 name["english"] = "CA Unicenter's File Transfer Service is running";
 script_name(english:name["english"]);
 
 desc["english"] = "CA Unicenter's File Transfer Service uses ports TCP:3104, UDP:4104 and
TCP:4105 for communication between its clients and other CA Unicenter
servers. These ports are open, meaning that CA Unicenter File Transfer
service is probably running, and is open for outside attacks.

Solution: Block those ports from outside communication

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "CA Unicenter's File Transfer Service is running";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 SecuriTeam");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_require_ports(3104, 4105);
 exit(0);
}

#
# The script code starts here
#

 if ((get_port_state(3104)) && (get_port_state(4105)) && (get_udp_port_state(4104)))
 {
  soctcp    = open_sock_tcp(3104);
  if(!soctcp)exit(0);
  else close(soctcp);
 
  soctcp     = open_sock_tcp(4105);
  if(!soctcp)exit(0);
  else close(soctcp);


  socudp4104 = open_sock_udp(4104);

  if (socudp4104)
  {
   send (socket:socudp4104, data:string("\r\n"));
   result = recv(socket:socudp4104, length:1000);
   if (strlen(result)>0)
   {
    set_kb_item(name:"Windows compatible", value:TRUE);
    security_hole(port:4104, protocol:"udp");
   }

  close(socudp4104);
 }
}
