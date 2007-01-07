#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10040);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2002-0128");
 script_bugtraq_id(3885);
 
 
 name["english"] = "cgitest.exe buffer overrun";
 name["francais"] = "cgitest.exe buffer overrun";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "There is a buffer overrun in
the 'cgitest.exe' CGI program, which will allow anyone to
execute arbitrary commands with the same privileges as the
web server (root or nobody).

Solution : remove it from /cgi-bin.

Risk factor : Serious";


 desc["francais"] = "Il y a un dépassement de buffer
dans le CGI 'cgitest.exe', qui permet à n'importe qui d'executer
des commandes arbitraires avec les memes privilèges que le 
serveur web (root ou nobody).

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the /cgi-bin/cgitest.exe buffer overrun";
 summary["francais"] = "Vérifie le dépassement de buffer de /cgi-bin/cgitest.exe";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
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

flag = 0;
directory = "";

foreach dir (cgi_dirs())
{
 if(is_cgi_installed_ka(item:string(dir, "/cgitest.exe"), port:port))
 {
  flag = 1;
  directory = dir;
  break;
 } 
}
 

if(safe_checks())
{
  if(flag)
  {
rep = "
There may be a buffer overrun in
the 'cgitest.exe' CGI program, which will allow anyone to
execute arbitrary commands with the same privileges as the
web server (root or nobody).

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : remove it from " + directory + "

Risk factor : Serious";
 security_hole(port:port, data:rep);
 exit(0);
 }
}

if(!flag)exit(0);
data = string(directory, "/cgitest.exe");
req = http_get(item:data, port:port);
if("User-Agent" >< req)
{
   req = ereg_replace(pattern:"(User-Agent: )(.*)$",
   		      replace:"\1"+crap(2600),
		      string:req);
   req = req + string("\r\n\r\n");		   
}
else
{
   req = req - string("\r\n\r\n");
   req = req + string("\r\nUser-Agent: ", crap(2600), "\r\n\r\n");
}
 
soc = http_open_socket(port);
if(soc)
{
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  if(!r)security_hole(port);
  http_close_socket(soc);
}

