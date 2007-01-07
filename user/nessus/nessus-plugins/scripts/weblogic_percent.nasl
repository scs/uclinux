#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# Licence : GPL v2
#

if(description)
{
 script_id(10698);
 script_version ("$Revision: 1.16 $");
 script_bugtraq_id(2513);
 name["english"] = "WebLogic Server /%00/ bug";
 name["francais"] = "WebLogic Server /%00/ bug";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Requesting a URL with '%00', '%2e', '%2f' or '%5c' appended to it
makes some WebLogic servers dump the listing of the page 
directory, thus showing potentially sensitive files.

An attacker may also use this flaw to view
the source code of JSP files, or other dynamic content.

Reference : http://www.securityfocus.com/bid/2513
Risk factor : High
Solution : upgrade to WebLogic 6.0 with Service Pack 1";

 script_description(english:desc["english"]);
 
 summary["english"] = "Make a request like http://www.example.com/%00/";
 summary["francais"] = "Fait une requête du type http://www.example.com/%00/";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 StrongHoldNet",
		francais:"Ce script est Copyright (C) 2001 StrongHoldNet");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

function http_getdirlist(itemstr, port) {
 soc = http_open_socket(port);
 if(soc)
 {
  buffer = http_get(item:itemstr, port:port);
  send(socket:soc, data:buffer);
  rbuf = http_recv(socket:soc);
  data = tolower(rbuf);
  if(("directory listing of" >< data) || ("index of" >< data))
  {
   if(strlen(itemstr) > 1) security_hole(port:port);
   exit(0);
  }
  http_close_socket(soc);
 }
 else exit(0);
}

port = get_kb_item("Services/www");
if(!port) port = 80;
if(get_port_state(port))
{
  http_getdirlist(itemstr:"/", port:port);
  http_getdirlist(itemstr:"/%2e/", port:port);
  http_getdirlist(itemstr:"/%2f/", port:port);
  http_getdirlist(itemstr:"/%5c/", port:port);
}
