# This script was quicky written by Michel Arboi <arboi@alussinan.org>
# starting from badblue_directory_traversal.nasl by SecurITeam.
#
# GPL
#
# Reference
# From:"Auriemma Luigi" <aluigi@pivx.com>
# To:bugtraq@securityfocus.com
# Subject: Apache 2.0.39 directory traversal and path disclosure bug
# Date: Fri, 16 Aug 2002 17:01:29 +0000

if(description)
{
 script_id(11092);
 script_version("$Revision: 1.11 $");
 script_bugtraq_id(5434);
 script_cve_id("CAN-2002-0661");
 name["english"] = "Apache 2.0.39 Win32 directory traversal";
 script_name(english:name["english"]);
 
 desc["english"] = "
A security vulnerability in Apache 2.0.39 on Windows systems
allows attackers to access files that would otherwise be 
inaccessible using a directory traversal attack.
A cracker may use this to read sensitive files or even execute
any command on your system.

Solutions: 
	- Upgrade to Apache 2.0.40
	- or install it on a Unix machine
	- or add in your httpd.conf, before the first 
	  'Alias' or 'Redirect' directive:
	RedirectMatch 400 \\\.\.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Apache 2.0.39 Win32 directory traversal";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

# 

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if (! get_port_state(port)) exit(0);

cginameandpath[0] = "/error/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cautoexec.bat";
cginameandpath[1] = "/error/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwinnt%5cwin.ini";
cginameandpath[2] = "/error/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cboot.ini";
cginameandpath[3] = "";


qc=1;
n = string("www/no404/", port);
r = get_kb_item(n);
if (r) qc=0;

for (i = 0; cginameandpath[i]; i = i + 1)
{ 
  u = cginameandpath[i];
  if(check_win_dir_trav(port: port, url:u, quickcheck: qc))
  {
    security_hole(port);
    exit(0);
  }
}

banner = get_http_banner(port: port);
if (! banner) exit(0);
if (egrep(string: banner, pattern:"^Server: *Apache(-AdvancedExtranetServer)?/2\.0\.[0-3][0-9]* *\(Win32\)"))
{
  m = "
A security vulnerability in Apache 2.0.39 on Windows systems
allows attackers to access files that would otherwise be 
inaccessible using a directory traversal attack.

** Nessus found that your server should be vulnerable according to
** its version number but could not exploit the flaw.
** You may have already applied the RedirectMatch wordaround.
** Anyway, you should upgrade your server to Apache 2.0.40

Risk factor : High/None";
  security_warning(port: port, data: m);
}
