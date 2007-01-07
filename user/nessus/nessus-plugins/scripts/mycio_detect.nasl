#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com> 
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10707);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "McAfee myCIO detection";
 script_name(english:name["english"]);
 
 desc["english"] = "We detected the presence of McAfee's myCIO HTTP Server.
The server provides other clients on the network with antivirus updates. 
Several security vulnerabilities have been found in the past in the myCIO 
product.

It is advisable that you block access to this port (TCP 6515) from untrusted 
networks.

Solution: Configure your firewall to block access to this port (TCP 6515). 

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "McAfee myCIO detection";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 family["english"] = "General";
 script_family(english:family["english"]);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 script_dependencie("find_service.nes");
 script_require_ports("Services/mycio", 6515);
 exit(0);
}

#
# The script code starts here
#

 port = get_kb_item("Services/mycio");
 if (!port) port = 6515;

 if (get_port_state(port))
 {
  soctcp6515 = open_sock_tcp(port);

  if (soctcp6515)
  {
   data = http_head(item:"/", port:port);
   resultsend = send(socket:soctcp6515, data:data);
   resultrecv = http_recv(socket:soctcp6515);
   if ("myCIO" >< resultrecv)
   {
     security_warning(port:port);
   }
  }
  close(soctcp6515);
 }
