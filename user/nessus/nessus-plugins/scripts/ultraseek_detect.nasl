#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com> 
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10791);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "Ultraseek Web Server Detect";
 script_name(english:name["english"]);
 
 desc["english"] = "
Ultraseek Web Server is running on this host. 
Ultraseek has been known to contain security vulnerabilities ranging from 
Buffer Overflows to Cross Site Scripting issues.

Solution: Make sure you are running the latest version of the Ultraseek 
Web Server or disable it if you do not use it.

Additional information:
http://www.securiteam.com/cgi-bin/htsearch?config=htdigSecuriTeamwords=Ultraseek

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Ultraseek Web Server Detect";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 family["english"] = "General";
 script_family(english:family["english"]);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 8765);
 exit(0);
}

#
# The script code starts here
#
 include("http_func.inc");

 port = get_kb_item("Services/www");
 if (!port) port = 8765;

 if (get_port_state(port))
 {
   banner = get_http_banner(port:port);
   if(!banner)exit(0);
   if ("Server: Ultraseek" >< banner)
   {
    security_warning(port);
   }
 }
