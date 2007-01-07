if(description)
{
 script_id(10877);
 script_cve_id("CVE-1999-1005", "CVE-1999-1006");
 script_bugtraq_id(879);
 script_version("$Revision: 1.10 $");
 name["english"] = "GroupWise Web Interface 'HELP' hole";
 script_name(english:name["english"]);
 
 desc["english"] = "
By modifying the GroupWise Web Interface HELP URL request,
it is possible to gain additional information on the
remote computer and even read local files from its hard
drive.

Risk factor : High
Solution : Contact your vendor for a patch
See also : http://www.securiteam.com/exploits/3I5QDQ0QAG.html
";

 script_description(english:desc["english"]);
 
 summary["english"] = "GroupWise Web Interface 'HELP' hole";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 SecurITeam");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

function check(req)
{
  req = http_get(item:req, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);
  
  if ("Could not find file SYS" >< buf)
  {
   	security_hole(port:port);
	return(1);
  }
  return(0);
}

port = get_kb_item("Services/www");
if(!port)port = 80;

cginameandpath[0] = string("/GW5/GWWEB.EXE?HELP=bad-request");
cginameandpath[1] = string("/GWWEB.EXE?HELP=bad-request");


i = 0;
if(get_port_state(port))
{
 for (i = 0; cginameandpath[i]; i = i + 1)
 { 
  url = cginameandpath[i];
  if(check(req:url))exit(0);
 }
}  else exit(0);



foreach dir (cgi_dirs())
{
cginameandpath[0] = string(dir, "/GW5/GWWEB.EXE?HELP=bad-request");
cginameandpath[1] = string(dir, "/GWWEB.EXE?HELP=bad-request");

 i = 0;
 for (i = 0; cginameandpath[i]; i = i + 1)
 { 
  url = cginameandpath[i];
  if(check(req:url))exit(0);
 }
}
