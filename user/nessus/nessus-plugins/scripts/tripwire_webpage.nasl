#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
# Modifications by rd :
#	- we read www/banner/<port> first
#	- egrep()
#	- no output of the version (redundant with the server banner)
#

if(description)
{
 script_id(10743);
 script_version ("$Revision: 1.9 $");

 name["english"] = "Tripwire for Webpages Detection";
 script_name(english:name["english"]);

 desc["english"] = "We detected the remote web server as running 
Tripwire for web pages under the Apache web server. This software 
allows attackers to gather sensitive information about your server 
configuration.

Solution: Modify the banner used by Apache by adding the option
'ServerTokens' to 'ProductOnly' in httpd.conf

Risk factor : Low

Additional information can be found at:
http://www.securiteam.com/securitynews/5RP0L1540K.html (Web Server banner removal guide)
";

 script_description(english:desc["english"]);

 summary["english"] = "Tripwire for Webpages Detect";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
 include("http_func.inc");
 
 port = get_kb_item("Services/www");
 if (!port) port = 80;
 if(!get_port_state(port))exit(0);
 banner = get_http_banner(port:port);


  if (egrep(string:banner, pattern:"^Server: Apache.* Intrusion/"))
  {
   security_warning(port);
  }
