#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10765);
script_cve_id("CAN-2001-0986");
 script_bugtraq_id(3339);
 script_version ("$Revision: 1.12 $");

name["english"] = "SQLQHit Directory Structure Disclosure";
 script_name(english:name["english"]);

 desc["english"] = "
The Sample SQL Query CGI is present. 
The sample allows anyone to structure a certain query that would retrieve
the content of directories present on the local server.

Solution: Use Microsoft's Secure IIS Guide (For IIS 4.0 or IIS 5.0 respectively) or  
Microsoft's IIS Lockdown tool to remove IIS samples.

Risk factor : Medium

Additional information:
http://www.securiteam.com/tools/5QP0N1F55Q.html (IIS Lookdown)
http://www.securiteam.com/windowsntfocus/5HP05150AQ.html (Secure IIS 4.0)
http://www.securiteam.com/windowsntfocus/5RP0D1F4AU.html (Secure IIS 5.0)
";

 script_description(english:desc["english"]);

 summary["english"] = "SQLQHit Directory Stracture Disclosure";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");


program[0] = "sqlqhit.asp";
program[1] = "SQLQHit.asp";

port = get_kb_item("Services/www");
if (!port) port = 80;

if(!get_port_state(port))exit(0);


foreach dir (cgi_dirs())
{
 for (j = 0; program[j] ; j = j + 1)
 {
  url = string(dir, "/", program[j], "?CiColumns=*&CiScope=webinfo");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);
  if (("VPATH" >< buf) && ("PATH" >< buf) && ("CHARACTERIZATION" >< buf))
    {
     security_hole(port:port);
     exit(0);
    }
  }
}

