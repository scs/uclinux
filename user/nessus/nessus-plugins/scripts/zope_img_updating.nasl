#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10569);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2000-0062");
 script_bugtraq_id(922);
 

 
 name["english"] = "Zope Image updating Method";
 name["francais"] = "Zope Image updating Method";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote web server is Zope < 2.2.5

There is a security issue in all releases
prior to version 2.2.5.

The issue involves incorrect protection of a data updating 
method on Image and File objects. Because the method is not 
correctly protected, it is possible for users with DTML 
editing privileges to update the raw data of a File or Image 
object via DTML though they do not have editing privileges 
on the objects themselves. 

*** Nessus solely relied on the version number of your
*** server, so if you applied the hotfix already,
*** consider this alert as a false positive.

Solution : Upgrade to Zope 2.2.5 or apply the hotfix available
at http://www.zope.org/Products/Zope/Hotfix_2000-12-18/security_alert
Risk factor : Serious";





 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Zope";
 summary["francais"] = "Vérifie la présence de Zope";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/zope");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);
banner = get_http_banner(port:port);

if(banner)
{
  if(egrep(pattern:"Server: .*Zope 2\.((0\..*)|(1\..*)|(2\.[0-4]))", 
  		string:banner))
     security_hole(port);
}

