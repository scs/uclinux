#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(11915);
 script_cve_id("CAN-2003-0542");
 script_version("$Revision: 1.1 $");
 
 name["english"] = "Apache < 1.3.29";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running a version of Apache which is older 
than 1.3.29

There are several flaws in this version, which may allow an attacker to 
possibly execute arbitrary code through mod_alias and mod_rewrite.

You should upgrade to 1.3.29 or newer.

*** Note that Nessus solely relied on the version number
*** of the remote server to issue this warning. This might
*** be a false positive

Solution : Upgrade to version 1.3.29
See also : http://www.apache.org/dist/httpd/Announcement.html
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Apache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
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
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-1][0-9]|2[0-8])))", string:serv))
 {
   security_hole(port);
 } 
}
