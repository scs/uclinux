if (description)
{
 script_id(10780);
 script_version ("$Revision: 1.12 $");
 script_name(english:"CGIEmail's Cross Site Scripting Vulnerability (cgicso)");
 desc["english"] = "
The remote host seems to be vulnerable to a security problem in 
CGIEmail (cgicso). 
The vulnerability is caused by inadequate processing of queries 
by CGIEmail's cgicso  that results in cross site scripting.

Solution:
Modify cgilib.c to contain a stripper function that will 
remove any HTML or JavaScript tags.

Risk factor : Low";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is vulnerable to the cgicso vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2001 SecurITeam");
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if (!port) port = 80;
if(!get_port_state(port))exit(0);


dir = make_list("/bin", "/cgi-local/cgiemail-1.4", "/cgi-local",
		"/cgi/cgiemail",  "/html/cgi-bin", "/cgi-local/cgiemail-1.6",
		cgi_dirs());
		

check = string("<script>vulnerable</script>");


foreach d (dir)
{
 url = string(d, "/cgicso");
 data = string(url, "?query=<script>vulnerable</script>");
 req = http_get(item:data, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if(!ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf))exit(0);

 if (check >< buf)
   {
    security_warning(port:port);
    exit(0);
   }
}
