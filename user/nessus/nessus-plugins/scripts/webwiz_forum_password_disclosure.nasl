#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref: 
#  Date: 17 Apr 2003 19:45:39 -0000
#  From: Uziel aka nuJIurpuM <Uziel@uziel.biz>
#  To: bugtraq@securityfocus.com
#  Subject: Web Wiz Forums all version db stealing


if(description)
{
 script_id(11542);
 script_bugtraq_id(7380);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "Web Wiz Forums database disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running Web Wiz Site Forum, a set of .asp
scripts to manage online forums.

This release comes with a wwforum.mdb database, usually located
under admin/ which contains sensitive information, such as the
user passwords and emails.

An attacker may use this flaw to gain unauthorized access to the 
remote forum site and potentially edit its content.

Solution : Prevent the download of .mdb files from your website.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for wwforum.mdb";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_kb_item("Services/www");
if(!port) port = 80;

if(!get_port_state(port))exit(0);


dirs = make_list(cgi_dirs(), "");

foreach d (dirs)
{
 req = http_get(item:string(d, "/admin/wwforum.mdb"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 
 if ( res == NULL ) exit(0);
 
 if("Standard Jet DB" >< res)
	{
 	 security_warning(port);
	 exit(0);
	 }
}
