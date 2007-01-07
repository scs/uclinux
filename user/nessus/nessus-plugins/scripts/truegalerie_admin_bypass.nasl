#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref: http://www.frog-man.org/tutos/TrueGalerie.txt

if(description)
{
 script_id(11582);
 script_bugtraq_id(7427);
 script_version ("$Revision: 1.2 $");

 name["english"] = "TrueGalerie admin access";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running TrueGalerie, an album management system
written in PHP.

There is a flaw in the version of TrueGalerie which may allow an attacker
to log in as the administrator without having to know the password, simply
by requesting the URL :
		/admin.php?loggedin=1
		
		
An attacker may use this flaw to gain administrative privileges on
this web server and modify its content.

Solution : Disable the option 'register_globals' in php.ini or replace
this set of CGI by something else
Risk factor : Serious";


 script_description(english:desc["english"]);
 
 summary["english"] = "logs into the remote TrueGalerie installation";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
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



function check(loc)
{
 req = http_get(item:string(loc, "/admin.php?loggedin=1"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(">DECONNEXION</a>" >< r &&
    "Liste des catégories" >< r)
 {
 	security_hole(port);
	exit(0);
 }
}


dirs = make_list(cgi_dirs(), "");
dirx = make_list();

foreach dir (dirs)
{
 dirx = make_list(dirx, dir, dir + "/album");
}

foreach dir (dirx)
{
 check(loc:dir);
}
