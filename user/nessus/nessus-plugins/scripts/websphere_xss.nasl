# base on cross_site_scripting.nasl, from various people
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID

if (description)
{
 script_id(11010);
 script_version("$Revision: 1.7 $");
 script_bugtraq_id(2401);
 script_name(english:"WebSphere Cross Site Scripting");
 desc["english"] = 
"The remote web server seems to be vulnerable to the Cross Site Scripting 
vulnerability. The vulnerability is caused by the result returned to the 
user when a non-existing file is requested (e.g. the result contains the 
JavaScript provided in the request).
The vulnerability would allow an attacker to make the server present the 
user with the attacker's JavaScript/HTML code.
Since the content is presented by the server, the user will give it 
the trust level of the server (for example,
the trust level of banks, shopping centers, etc. would usually be high).

Risk factor : Medium

Solution : Upgrade to the latest version of WebSphere
";


 script_description(english:desc["english"]);
 script_summary(english:"Determine if the remote host is vulnerable to Cross Site Scripting vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"(c) 2002 Renaud Deraison");
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ibm-http");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;

if(!get_port_state(port)) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

req = http_get(item:"/../<SCRIPT>alert('Vulnerable')</SCRIPT>", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if( res == NULL ) exit(0);
if("<SCRIPT>alert('Vulnerable')</SCRIPT>" >< res) security_hole(port);
