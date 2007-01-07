#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# Modified by Georges Dagousset <georges.dagousset@alert4web.com> :
#   - port 1241 (IANA) added
#   - rcv test is more strict
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10147);
 script_version ("$Revision: 1.19 $");
 
 name["english"] = "A Nessus Daemon is running";
 script_name(english:name["english"]);
 
 desc["english"] = "The port TCP:3001 or TCP:1241 is open, and since this is the default port
for the Nessus daemon, this usually indicates a Nessus daemon is running,
and open for the outside world.
An attacker can use the Nessus Daemon to scan other site, or to further
compromise the internal network on which nessusd is installed on.
(Of course the attacker must obtain a valid username and password first, or
a valid private/public key)

Solution: Block those ports from outside communication, or change the
default port nessus is listening on.

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "A Nessus Daemon is running";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports(1241, 3001);
 script_dependencies("find_service.nes");
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");
  
function probe(port)
{
  supported = "";
  p[0] = "< NTP/1.2 >";
  #p[1] = "< NTP/1.0 >";


  #
  # We don't want to be fooled by echo & the likes
  #
  soc = open_sock_tcp(port);
  if(soc)
  {
    send(socket:soc, data:string("TestThis\r\n"));
    r = recv_line(socket:soc, length:10);
    if("TestThis" >< r)return(0);
    close(soc);
  }
  
  

  for(count=0; p[count] ; count=count+1)
  {
   soc = open_sock_tcp(port);
   if (soc)
   {
    senddata = string(p[count],"\n");
    send(socket:soc, data:senddata);
    recvdata = recv_line(socket:soc, length:20);
    if (ereg(pattern:string("^", p[count]), string:recvdata))
		supported = string(supported,p[count]);
    else 	
    		count = max + 1;
    close(soc);
   }
   else count = max + 1;
  }
  if (strlen(supported) > 0)
  {
    security_warning(port:port, data:string("A Nessus Daemon is listening on this port."));
    register_service(port: port, proto: "nessus");
  }
}


port = get_kb_item("Services/unknown");
if(port)
{
 if (known_service(port: port)) exit(0); 
 if(get_port_state(port))
  probe(port:port);
}
else
{
 if(get_port_state(1241))
  probe(port:1241);
 if(get_port_state(3001))
  probe(port:3001);
 
}
