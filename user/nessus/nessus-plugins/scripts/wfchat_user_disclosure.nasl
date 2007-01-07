#
# (C) Tenable Network Security
#
# SEE:http://lists.insecure.org/lists/bugtraq/2003/Mar/0271.html
#

if(description)
{
 script_id(11688);
 script_bugtraq_id(7147);
 script_version ("$Revision: 1.4 $");
 name["english"] = "WF-Chat User Account Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The WF-Chat allows an attacker to view user account by doing:
http://[somehost]/chat/!nicks.txt 
http://[somehost]/chat/!pwds.txt 

Solution : Delete this CGI
Risk factor : Serious";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of !pwds.txt";
 summary["francais"] = "Vérifie la présence de !pwds.txt";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "httpver.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}
#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);

dirs = make_list("/chat", "", cgi_dirs());
foreach dir (dirs)
{
 req = http_get(item:dir + "/!pwds.txt", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res))
 {
  idx = stridx(res, string("\r\n\r\n"));
  data = substr(res, idx, strlen(res));
  notme = egrep(pattern:"^[^ ].*$", string:data);
  if(notme == NULL ){
   req = http_get(item:dir + "/chatlog.txt", port:port);
   res = http_keepalive_send_recv(port:port, data:req);
   if(res == NULL ) exit(0);
   if(egrep(pattern:"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ .[0-9].*", string:res))
   {
   security_hole(port);
   exit(0);
   }
  }
 }
}
