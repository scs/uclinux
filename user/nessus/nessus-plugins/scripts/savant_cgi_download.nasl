# This script was written by Noam Rathaus <noamr@securiteam.com>

if (description)
{
 script_id(10623);
 script_version ("$Revision: 1.14 $");
 script_bugtraq_id(1313);
 script_cve_id("CVE-2000-0521");
 script_name(english:"Savant original form CGI access");
 desc["english"] = "
A security vulnerability in the Savant web server allows attackers to download the original form of CGIs (unprocessed).
This would allow them to see any sensitive information stored inside those CGIs.

Solution:
The newest version is still vulnerable to attack (version 2.1), it would be recommended that users cease to use this product.

Additional information:
http://www.securiteam.com/exploits/Savant_Webserver_exposes_CGI_script_source.html

Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is Savant web server, and whether it is vulnerable to attack"); script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses",
     	       francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if (!port) port = 80;

if (get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner)exit(0);

 if ("Server: Savant/">< banner)
 {
  foreach dir (cgi_dirs())
  {
  if (is_cgi_installed_ka(port:port, item:string(dir, "/cgitest.exe")))
  {
   data = http_get(item:string(dir, "/cgitest.exe"), port:port);

   soctcp80 = http_open_socket(port);
   resultsend = send(socket:soctcp80, data:data);
   resultrecv = http_recv(socket:soctcp80);
   http_close_socket(soctcp80);
   if ((resultrecv[0] == string("M")) && (resultrecv[1] == string("Z"))) {
   security_hole(port:port);}
  }
  else
  {
   security_warning(port:port);
  }
  }
 }
}
