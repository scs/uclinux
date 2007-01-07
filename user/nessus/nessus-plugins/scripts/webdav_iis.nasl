#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
  script_id(10526);
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(1756);
  script_cve_id("CVE-2000-0951");
  name["english"] = "IIS : Directory listing through WebDAV";
  name["francais"] = "IIS : Listing du contenu d'un repertoire avec WebDAV";

  script_name(english:name["english"], francais:name["francais"]);
  desc["english"] = "
It is possible to retrieve the listing of the remote 
directories accessible via HTTP, rather than their index.html, 
using the Index Server service which provides WebDav capabilities
to this server.

This problem allows an attacker to gain more knowledge
about the remote host, and may make him aware of hidden
HTML files.

Solution : disable the Index Server service, or
see http://www.microsoft.com/technet/support/kb.asp?ID=272079
Risk factor : Low";

  desc["francais"] = "
Il est possible d'obtenir la liste du contenu des repertoires
distants accessibles par HTTP, plutot que leur fichier index.html,
en utilisant le serveyr de services d'indexage (Index Server).

 Ce problème permet à un pirate d'obtenir plus d'informations
sur la machine attaquée, ainsi que de découvrir la présence de
fichiers HTML cachés.

Solution : désactivez le serveur de services d'indexage, ou lisez
http://www.microsoft.com/technet/support/kb.asp?ID=272079

Facteur de risque : Faible";

 script_description(english:desc["english"], francais:desc["francais"]);

 summary["english"] = "Checks the presence of the Index Server service";
 summary["francais"] = "Vérifie la présence du serveur d'indexage";
 script_summary(english:summary["english"], francais:summary["francais"]);
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
     	 	  francais:"Ce script est Copyright (C) 2000 Renaud Deraison");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";

 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;

if(get_port_state(port))
{
  soc = http_open_socket(port);
  if(soc)
  {
  quote = raw_string(0x22);
  req = string("SEARCH / HTTP/1.1\r\n",
    	     "Host: ", get_host_name(), "\r\n",
	     "Content-Type: text/xml\r\n",
	     "Content-Length: 133\r\n\r\n",
	     "<?xml version=", quote, "1.0", quote, "?>\r\n",
	     "<g:searchrequest xmlns:g=", quote, "DAV:", quote, ">\r\n",
	     "<g:sql>\r\n",
	     "Select ", quote, "DAV:displayname", quote, " from scope()\r\n",
	     "</g:sql>\r\n",
	     "</g:searchrequest>\r\n");
  send(socket:soc, data:req);
  result = recv_line(socket:soc, length:2048);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if("HTTP/1.1 207 " >< result)
   {
    if(("DAV:" >< r) && ((".asp" >< r)||(".inc" >< r)))security_warning(port);
   }
  }
}
