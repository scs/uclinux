if (description)
{
 script_id(11020);
 script_cve_id("CVE-2001-0319");
 script_bugtraq_id(2350);
 script_version("$Revision: 1.6 $");
 script_name(english:"NetCommerce SQL injection");
 desc["english"] = 
"
The macro orderdspc.d2w in the remote IBM Net.Commerce 3x
is vulnerable to an SQL injection attack.

An attacker may use it to abuse your database in many ways.


Solution : http://www-4.ibm.com/software/webservers/commerce/netcomletter.html
Risk factor : High
";


 script_description(english:desc["english"]);
 script_summary(english:"Determine if the remote host is vulnerable to Cross Site Scripting vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"(c) 2002 Renaud Deraison");
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ibm-http");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);
req = http_get(item:"/cgi-bin/ncommerce3/ExecMacro/orderdspc.d2w/report?order_rn=9';", port:port);


expect1 = "A database error occurred.";
expect2 = "SQL Error Code";


soc = http_open_socket(port);
if(soc)
{
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(socket:soc);
 if((expect1 >< r) && (expect2 >< r))security_hole(port);
}
