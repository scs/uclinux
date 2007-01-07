#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref: 
# From: "drG4njubas" <drG4nj@mail.ru>
# To: <bugtraq@securityfocus.com>
# Subject: Web Wiz Site News realease v3.06 administration access.
# Date: Mon, 14 Apr 2003 17:19:03 +0400


if(description)
{
 script_id(11533);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Web Wiz Site News database disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running Web Wiz Site News, a set of .asp
scripts to manage a news web site.

This release comes with a news.mdb database, usually located
under /news/ which contains sensitive information, such as the
news site administrator password or URLs to several news stories.

An attacker may use this flaw to gain unauthorized access to the 
remote news site and potentially edit it.

Solution : Prevent the download of .mdb files from your website.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for news.mdb";
 
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
 req = http_get(item:string(d, "/news/news.mdb"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 
 if ( res == NULL ) exit(0);
 
 if("Standard Jet DB" >< res)
	{
 	 security_warning(port);
	 exit(0);
	 }
}
