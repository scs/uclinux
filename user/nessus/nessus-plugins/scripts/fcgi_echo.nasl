#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10838);
 script_version ("$Revision: 1.3 $");
 name["english"] = "FastCGI Echo.exe Cross Site Scripting";
 name["francais"] = "FastCGI Echo.exe Cross Site Scripting";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] =  "
Two sample CGI's supplied with FastCGI are vulnerable 
to cross-site scripting attacks. FastCGI is an 'open extension to CGI 
that provides high performance without the limitations of server 
specific APIs', and is included in the default installation of the 
'Unbreakable' Oracle9i Application Server. Various other web servers 
support the FastCGI extensions (Zeus, Pi3Web etc).

Two sample CGI's are installed with FastCGI, echo.exe and echo2.exe. 
Both of these CGI's output a list of environment variables and PATH 
information for various applications. They also display any parameters 
that were provided to them. Hence, a cross site scripting attack can be 
performed via a request such as: 

http://www.someserver.com/fcgi-bin/echo2.exe?blah=<SCRIPT>alert(document.domain)</SCRIPT>  

Solution: 

Always remove sample applications from production servers.

Risk factor : Low to High, depending on the function of the web site";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for FastCGI Echo.exe Cross Site Scripting";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore",
		francais:"Ce script est Copyright (C) 2002 Matt Moore");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(get_port_state(port))
{ 
 req = http_get(item:"/fcgi-bin/echo.exe?foo=<SCRIPT>alert(document.domain)</SCRIPT>", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("QUERY_STRING=foo=<SCRIPT>alert(document.domain)</SCRIPT>" >< r) 

 	security_hole(port);

 }
}
