#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11769);
 script_version ("$Revision: 1.1 $");
 script_bugtraq_id(7999, 8000, 8001);

 
 name["english"] = "Zope Invalid Query Path Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Zope web server may be forced into disclosing its
physical path when it receives bad arguments for several
example CGIs included in the installation.

Solution : Delete the directory /Examples
Risk Factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Zope Examples directory";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80, 8080);
 script_require_keys("www/zope");
 exit(0);
}

# The script code starts here

include("http_func.inc");
port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port)) port = 8080;
if(!get_port_state(port)) exit(0);


s = http_open_socket(port);
if (! s) exit(0);

req = http_get(port: port, item: "/Examples/ShoppingCart/addItems?orders.id%3Arecords=510-007&orders.quantity%3Arecords=&orders.id%3Arecords=510-122&orders.quantity%3Arecords=0&orders.id%3Arecords=510-115&orders.quantity%3Arecords=0");
send(socket: s, data: req);
a = http_recv(socket: s);

if("invalid literal for int()" >< a && "Publish.py"  >< a)
{
  security_warning(port);
  }
http_close_socket(s);
