#
# (C) Tenable Network Security
#
# Ref:
# http://www.securityfocus.com/advisories/5887
# http://www.php.net/ChangeLog-4.php
#

if(description)
{
 script_id(11850);
 script_bugtraq_id(8693, 8696);
 script_cve_id("CAN-2003-0442");

 script_version("$Revision: 1.4 $");
 name["english"] = "php4 multiple flaws";
 

 script_name(english:name["english"]);
 desc["english"] = "
The remote host is running a version of PHP which is
older than 4.3.3.

All version of PHP 4 older than 4.3.3 are vulnerable to multiple integer
overflow vulnerabilities which might allow an attacker to execute arbitrary
commands on this host. Another problem may also invalidate safe_mode.

See also : http://www.php.net/ChangeLog-4.php
Solution : Upgrade to PHP 4.3.3
Risk factor : Medium";



 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of PHP";
 summary["francais"] = "Vérifie la version de PHP";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
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
 banner = get_http_banner(port:port);
 if(!banner)exit(0);
 serv = strstr(banner, "Server");
 if(ereg(pattern:".*PHP/4\.([0-2]\..*|3\.[0-2]))[^0-9]*", string:serv))
 {
   security_warning(port);
   exit(0);
 }
 else
 {
   serv = strstr(banner, "X-Powered-By:");
   if(ereg(pattern:".*PHP/([4\.([0-2]\..*|3\.[0-1]))[^0-9]*", string:serv))
   {
     security_warning(port);
     exit(0);
   }
 }
}
