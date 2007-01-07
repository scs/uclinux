#
# (C) Tenable Network Security
#
#


if(description)
{
 script_id(11652);
 script_version ("$Revision: 1.2 $");
 

 name["english"] = "Mantis Detection";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This script detects whether the mantis bug tracking
system is running on the remote host, and extracts its 
version if it is.

Risk factor : None";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of mantis";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
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

foreach d (make_list("", "/bugs", "/mantis", cgi_dirs()))
{
 req = http_get(item:string(d, "/login_page.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 res = egrep(pattern:"http://mantisbt\.sourceforge\.net", string:res, icase:TRUE);
 if( res )
 {
  vers = ereg_replace(pattern:".*Mantis ([^<]*).*", string:res, replace:"\1", icase:TRUE);
  set_kb_item(name:string("www/", port, "/mantis/version"),
  	      value:vers);
	      
  rep = "The remote host is running Mantis " + vers + " under /" + d;
  security_note(port:port, data:rep);
  exit(0);     
 }
} 
