#
# (C) Tenable Network Security

if(description)
{
 script_id(11692);
 script_bugtraq_id(7766);
 script_version("$Revision: 1.2 $");
 name["english"] = "WebStores 2000 browse_item_details.asp SQL injection";
 script_name(english:name["english"]);

 desc["english"] = "
The remote web server is running WebStore 2000, a set of ASP
scripts designed to set up an e-commerce store.

There is a flaw in the version of WebStore which is being
used which may allow an attacker to make arbitrary SQL statements
to the backend database being used.

An attacker may use this flaw to take the control of your
database.


Solution : None at this time
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "WebStores 2000 SQL injection";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "httpver.nasl", "no404.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");



 
port = get_kb_item("Services/www");
if(!port)port = 80;

if(!get_port_state(port))exit(0);


dirs = make_list("", "/store", cgi_dirs());
foreach dir (dirs)
{
 req = http_get(item:dir + "/browse_item_details.asp?Item_ID='", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res) && 
    "Microsoft OLE DB Provider" >< res ) { security_hole(port); exit (0);}
}
