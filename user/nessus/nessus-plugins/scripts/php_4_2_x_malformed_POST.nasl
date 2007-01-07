#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#
# Incidentally covers CAN-2002-0985 and 986
#

if(description)
{
 script_id(11050);

 script_version("$Revision: 1.11 $");
 script_bugtraq_id(5278);
 script_cve_id("CAN-2002-0986");
 
 name["english"] = "php 4.2.x malformed POST ";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of PHP earlier
than 4.2.2.

The new POST handling system in PHP 4.2.0 and 4.2.1 has
a bug which allows an attacker to disable the remote server
or to compromise it.

Solution : Upgrade to PHP 4.2.2 or downgrade to 4.1.2
Risk factor : High";




 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of PHP";
 summary["francais"] = "Vérifie la version de PHP";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(get_port_state(port))
{
 if(!safe_checks())
 {
  files = get_kb_list(string("www/", port, "/content/extensions/php*"));
  if(isnull(files))file = "/index.php";
  else file = files[0];
  
  if(is_cgi_installed(item:file, port:port))
  {
   req = string("POST ", file, " HTTP/1.1\r\n",
        "Referer: ", get_host_name(), "\r\n",
        "Connection: Keep-Alive\r\n",
        "Host: ", get_host_name(), "\r\n",
        "Content-type: multipart/form-data; boundary=nessus\r\n",
        "Content-length: 45\r\n\r\n",
        "--nessus\r\n",
        "Content-Disposition: foo=bar;\r\n",
        "\r\n\r\n");
    soc = http_open_socket(port);
    if(!soc)exit(0);
    
    send(socket:soc, data:req);
    r = http_recv(socket:soc);
    http_close_socket(soc);
    if(!r)security_hole(port);
    exit(0);
  }
 }
 
 
 banner = get_http_banner(port:port);
 if(!banner)exit(0);
 serv = strstr(banner, "Server");
 if(ereg(pattern:".*PHP/4\.2\.[01][^0-9]*", string:serv))
 {
   security_hole(port);
   exit(0);
 }
 else
 {

   serv = strstr(banner, "X-Powered-By:");
   if(ereg(pattern:".*PHP/4\.2\.[01][^0-9]*", string:serv))
   {
     security_hole(port);
     exit(0);
   }
 }
}
