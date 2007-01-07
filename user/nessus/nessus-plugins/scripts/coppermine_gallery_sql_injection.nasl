#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(11564);
 script_bugtraq_id(7471);
 script_version ("$Revision: 1.2 $");


 name["english"] = "Coppermine Gallery SQL injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Coppermine Gallery - a set of PHP scripts
designed to handle galleries of pictures.

This product has a vulnerability which allows an attacker to insert
a rogue SQL query which may allow it to view arbitrary images on this
server or even take the control of the database.

Solution : Upgrade to Coppermine 1.1 beta 3
Risk factor : Medium";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of db_input.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "no404.nasl");
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

gdir = make_list(cgi_dirs());
dirs = make_list("", "/gallery");
foreach d (gdir)
{
  dirs = make_list(dirs, string(d, "/gallery"), d);
}


  foreach dir (dirs)
  {
   req = http_get(item:string(dir, "/db_input.php"), port:port);
   res = http_keepalive_send_recv(port:port, data:req);
   if( res == NULL ) exit(0);
   if(egrep(pattern:"Coppermine Photo Gallery.* v1\.(0.*|1 (devel|Beta [12]))", string:res, icase:TRUE))
 	{
	security_warning(port);
	exit(0);
	}
  }

