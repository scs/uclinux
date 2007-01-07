#
# (C) Tenable Network Security
#
# Ref: http://nagoya.apache.org/bugzilla/show_bug.cgi?id=22030
#
# Date: 26 Sep 2003 23:03:12 -0000
# From: Mandrake Linux Security Team <security@linux-mandrake.com>
# To: bugtraq@securityfocus.com
# Subject: MDKSA-2003:096 - Updated apache2 packages fix CGI scripting deadlock





if(description)
{
 script_id(11853);
 script_version("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0061", "CAN-2003-0789", "CAN-2003-0542");
 script_bugtraq_id(8926);
 name["english"] = "Apache < 2.0.48";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running a version of Apache 2.x which is older 
than 2.0.48.

This version is vulnerable to a bug which may allow a rogue CGI to disable
the httpd service by issuing over 4K of data to stderr.

To exploit this flaw, an attacker would need the ability to upload a rogue
CGI script to this server and to have it executed by the Apache daemon (httpd).

Solution : Upgrade to version 2.0.48 when it is available
See also : http://nagoya.apache.org/bugzilla/show_bug.cgi?id=22030 
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Apache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);


banner = get_http_banner(port: port);
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.([0-9][^0-9]|[0-3][0-9]|4[0-7])", string:serv))
 {
   security_warning(port);
 }
