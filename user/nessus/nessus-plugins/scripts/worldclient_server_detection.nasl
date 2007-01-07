#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Currently no testing scripts for WorldClient vulnerabilities.  Added
#      notes of the current list of WorldClient vulnerabilities
#

if(description)
{
 script_id(10745); 
 script_version ("$Revision: 1.10 $");

 name["english"] = "WorldClient for MDaemon Server Detection";
 script_name(english:name["english"]);

 desc["english"] = "We detected the remote web server is 
running WorldClient for MDaemon. This web server enables attackers 
with the proper username and password combination to access locally 
stored mailboxes.

In addition, earlier versions of WorldClient suffer from buffer overflow 
vulnerabilities, and web traversal problems (if those are found the Risk 
factor is higher).  Current WorldClient vulnerabilities on Bugtraq are:
Bugtraq IDs 823, 1462, 2478, 4687, 4689

Solution: Make sure all usernames and passwords are adequately long and 
that only authorized networks have access to this web server's port number 
(block the web server's port number on your firewall).

Risk factor : Low

For more information see:
http://www.securiteam.com/cgi-bin/htsearch?config=htdigSecuriTeam&words=WorldClient";

 script_description(english:desc["english"]);

 summary["english"] = "Check for WorldClient for MDaemon";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "httpver.nasl");
 script_require_ports("Services/www", 3000);
 exit(0);
}

#
# The script code starts here
#
 include("http_func.inc");
 include("misc_func.inc");
 
 ports = add_port_in_list(list:get_kb_list("Services/www"), port:3000);
 foreach port (ports)
 {
 banner = get_http_banner(port:port);
 if(banner)
 {

  #display(buf);
  if (egrep(pattern:"^Server: WDaemon/", string:banner))
  {
   security_note(port);
   buf = strstr(banner, "WDaemon/");
   buf = banner - "WDaemon/";
   subbuf = strstr(buf, string("\r\n"));
   buf = buf - subbuf;
   version = buf;

   buf = "Remote WorldClient server version is: ";
   buf = buf + version;
   if (version < "4")
   {
    # I'm wondering if this should not be in another plugin (rd) 
    report = string("\nThis version of WorldClient contains serious security vulnerabilities.\n",
    "It is advisable that you upgrade to the latest version\n",
    "Risk factor : High\n",
    "Solution : Upgrade\n");
    security_hole(data:report, port:port);
    }
   }
  }
 }

