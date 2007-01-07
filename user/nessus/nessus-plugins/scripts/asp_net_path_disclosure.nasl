#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10843);
 script_version ("$Revision: 1.5 $");
 name["english"] = "ASP.NET path disclosure";

 script_name(english:name["english"]);
 
 desc["english"] = "
ASP.NET is vulnerable to a path disclosure vulnerability. This 
allows an attacker to determine where the remote web root is
physically stored in the remote file system, hence gaining
more information about the remote system.

Solution : There was no solution ready when this vulnerability was written;
Please contact the vendor for updates that address this vulnerability.
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for ASP.NET Path Disclosure Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(get_port_state(port))
{ 
 req = http_get(item:string("/a%5c.aspx"), port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("Server Error" >< r)
 {
  r = strstr(r, "Invalid file name");
  end = strstr(r, string("\n"));
  str = r - end;
  path = ereg_replace(pattern:".*Invalid file name for monitoring: (.*)</title>",
		    string:str,
		    replace:"\1");
  if(ereg(string:path, pattern:"[A-Z]:\\.*", icase:TRUE))security_warning(port);
  }
 }
}
