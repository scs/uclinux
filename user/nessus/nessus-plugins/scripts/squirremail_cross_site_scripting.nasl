#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#
# Did not really check CAN-2002-1276, since it`s the same kind of problem.
#

if (description)
{
 script_id(11415);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CAN-2002-1276", "CAN-2002-1341");
 script_bugtraq_id(7019,6302);
 script_name(english:"SquirrelMail's Cross Site Scripting");
 desc["english"] = "
The remote host seems to be vulnerable to a security problem in 
SquirrelMail. Its read_body.php didn't filter out user input for 
'filter_dir' and 'mailbox', making a xss attack possible.

Solution:
Upgrade to a newer version.

Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Xue Yong Zhi");
 script_dependencie("find_service.nes", "no404.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if (!port) port = 80;
if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);


dir = make_list(cgi_dirs(), "");
		

check1 = string("<script>alert(document.cookie)</script>");
check2 = string("%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E");

foreach d (dir)
{
 url = string(d, "/read_body.php");
 data = string(url, "?mailbox=", 
"<script>alert(document.cookie)</script>&passed_id=",
"<script>alert(document.cookie)</script>&",
"startMessage=1&show_more=0");
 req = http_get(item:data, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if(!ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf))exit(0);
 if (check1 >< buf)
   {
    security_warning(port:port);
    exit(0);
   }
# if (check2 >< buf)
#   {
#    security_hole(port:port);
#    exit(0);
#   }
}
