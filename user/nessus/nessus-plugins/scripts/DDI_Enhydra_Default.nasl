#
# This script was written by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11202);
 script_version("$Revision: 1.2 $");

 name["english"] = "Enhydra Multiserver Default Password";
 script_name(english:name["english"]);

 desc["english"] = "

This system appears to be running the Enhydra application
server configured with the default administrator password
of 'enhydra'. A potential intruder could reconfigure this 
service and use it to obtain full access to the system.

Solution: Please set a strong password of the 'admin' account.

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Enhydra Multiserver Default Admin Password";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Digital Defense Inc.");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 8001);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
port = get_kb_item("Services/www");
if (!port) port = 8001;

if(get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if (soc)
  {
    req = http_get(item:"/Admin.po?proceed=yes", port:port);
    req = req - string("\r\n\r\n");
    req = string(req, "\r\nAuthorization: Basic YWRtaW46ZW5oeWRyYQ==\r\n\r\n");
    send(socket:soc, data:req);
    buf = http_recv(socket:soc);
    close(soc);
    
    if("Enhydra Multiserver Administration" >< buf)
    {
        security_hole(port);
    }   
  }
 }
