#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10140);
 script_version ("$Revision: 1.20 $");
 script_bugtraq_id(734);
 script_cve_id("CVE-1999-0931");
 name["english"] = "MediaHouse Statistic Server Buffer Overflow";
 name["francais"] = "MediaHouse Statistic Server Buffer Overflow";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to overflow a buffer in a CGI
on the remote server by making the request :

	GET /ss?setsite=aaaa[....]aaaa

An attacker may use this flaw to execute arbitrary
code on this server.

Solution : There was no solution ready when this vulnerability was written;
Please contact the vendor for updates that address this vulnerability.
Workaround : see http://w1.855.telia.com/~u85513179/index.html.

Risk factor : High";


 desc["francais"] = "
Il s'est avéré possible de trop remplir un
buffer dans un CGI distant en faisant la requête :

	GET /ss?setsite=aaaa[...]aaaa
	
Un pirate peut utiliser ce problème pour executer
du code arbitraire sur ce serveur.

Solution : aucune à cette date.
Moyen de contourner le probleme : 
	cf http://w1.855.telia.com/~u85513179/index.html

Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Overflow of /ss?";
 summary["francais"] = "Dépassement de /ss?";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_keys("www/statistics-server");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = is_cgi_installed("/ss");
if(port)
{
 soc = http_open_socket(port);
 if(soc)
 {
   req = string("/ss?setsite=", crap(5000));
   req = http_get(item:req, port:port);
   send(socket:soc, data:req);
   b = http_recv(socket:soc);
   if(!b)
   { 
    security_hole(port);
   }
  http_close_socket(soc);
  }
}

