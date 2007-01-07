#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(11137);
 script_cve_id("CAN-2002-0839", "CAN-2002-0840", "CAN-2002-0843");
 script_bugtraq_id(5847, 5884, 5995, 5996);
 script_version("$Revision: 1.9 $");
 
 name["english"] = "Apache < 1.3.27";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running a version of
Apache which is older than 1.3.27

There are several flaws in this version, you should
upgrade to 1.3.27 or newer.

*** Note that Nessus solely relied on the version number
*** of the remote server to issue this warning. This might
*** be a false positive

Solution : Upgrade to version 1.3.27
See also : http://www.apache.org/dist/httpd/Announcement.html
Risk factor : Medium";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of Apache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
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
if(get_port_state(port))
{
banner = get_http_banner(port: port);
if(!banner)exit(0);
serv = strstr(banner, "Server:");
if(!serv)exit(0);
# ibm 1.3.19.4 equates to apache 1.3.27 (sorta) so anything > 1.3.19.4 is ok
#IBM_HTTP_SERVER/1.3.19.4  Apache/1.3.20 (Unix) (this is apache 1.3.20 PATCHED)
# i HOPE this ereg is fine

if(ereg(pattern:"^Server: IBM_HTTP_SERVER\/([2-9]|1\.[4-9]\.|1\.[1-9][0-9]\.|1\.3\.[2-9][0-9]\.|1\.3\.19\.[4-9][^0-9])",string:serv))exit(0);


 
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-1][0-9]|2[0-6])))", string:serv))
{
   security_warning(port);
}
}
