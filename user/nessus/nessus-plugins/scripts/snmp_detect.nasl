#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#
# Changes by rd : improved the SNMP detection (done using
# a null community name)
#

if(description)
{
 script_id(10265);
 script_version ("$Revision: 1.17 $");
 
 name["english"] = "An SNMP Agent is running";
 script_name(english:name["english"]);
 
 desc["english"] = "Either (or both) of the ports UDP:161 and UDP:162 are open. This usually
indicates an SNMP agent is present. Having such an agent open to outside
access may be used to compromise sensitive information, and can be used to
cause a Denial of Service attack. Certain SNMP agents may be
vulnerable to root compromise attacks.

More Information:
http://www.securiteam.com/exploits/Patrol_s_SNMP_Agent_3_2_can_lead_to_root_compromise.html

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "An SNMP Agent is running";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 SecuriTeam");
 family["english"] = "SNMP";
 script_family(english:family["english"]);
 
 exit(0);
}

#
# The script code starts here
#

 if(!(get_udp_port_state(161)))exit(0);
 
 socudp161 = open_sock_udp(161);
 socudp162 = open_sock_udp(162);
 

 if (socudp161)
 {
 
  req = raw_string(
  	      0x30, 0x82, 0x00, 0x26, 0x02, 0x01,
  0x00, 0x04, 0x00, 0xA1, 0x82, 0x00, 0x1D, 0x02,
  0x04, 0x1D, 0x99, 0x1E, 0xF4, 0x02, 0x01, 0x00,
  0x02, 0x01, 0x00, 0x30, 0x82, 0x00, 0x0D, 0x30,
  0x82, 0x00, 0x09, 0x06, 0x05, 0x2B, 0x06, 0x01,
  0x02, 0x01, 0x05, 0x00);
  send(socket:socudp161, data:req);
  send(socket:socudp162, data:string("\r\n"));
  
  result = recv(socket:socudp161, length:1000, timeout:1);
  if (result)
  {
   data = "A SNMP server is running on this host";
   security_warning(port:161, data:data, protocol:"udp");
   set_kb_item(name:"SNMP/running", value:TRUE);
  }
 }
 
 if (socudp162)
 {
  result = recv(socket:socudp162, length:1, timeout:1);
  if (strlen(result)>1)
  {
   data = "SNMP Trap Agent port open, it is possible to
overflow the SNMP Traps log with fake traps (if proper community
names are known), causing a Denial of Service";
   security_warning(port:162, data:data, protocol:"udp");
  }
 }

 close(socudp161);
 close(socudp162);


