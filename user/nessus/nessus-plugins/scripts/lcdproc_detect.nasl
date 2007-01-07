#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10379);
 script_version ("$Revision: 1.4 $");
 name["english"] = "LCDproc server detection";
 script_name(english:name["english"]);
 
 desc["english"] = "LCDproc (http://lcdproc.omnipotent.net) is a 
system that is used to display system information and other data 
on an LCD display (or any supported display device, including curses 
or text)
 
The LCDproc version 4.0 and above uses a client-server protocol, allowing 
anyone with access to the LCDproc server to modify the displayed content.

Risk factor : Low
Solution: Disable access to this service from outside by disabling 
 access to TCP port 13666 (default port used)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Find the presence of LCDproc";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
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
  req = string("hello");
  soc = open_sock_tcp(port);
  if(soc)
  {
   send(socket:soc, data:req);
   result = recv(socket:soc, length:4096);
   
   if("connect LCDproc" >< result)
   {
    resultrecv = strstr(result, "connect LCDproc ");
    resultsub = strstr(resultrecv, string("lcd "));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "connect LCDproc ";
    resultrecv = resultrecv - "lcd ";

    banner = "LCDproc version: ";
    banner = banner + resultrecv;
    banner = banner + "\n";

    security_warning(port:port, data:banner);
    exit(0);
   }
  }
}

