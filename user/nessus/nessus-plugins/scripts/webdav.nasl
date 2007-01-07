#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
  script_id(10505);
 script_version ("$Revision: 1.12 $");
 script_bugtraq_id(1656);
  script_cve_id("CVE-2000-0869");
  
  name["english"] = "Directory listing through WebDAV";
  name["francais"] = "Listing du contenu d'un repertoire avec WebDAV";

  script_name(english:name["english"], francais:name["francais"]);
  desc["english"] = "
The WebDAV module can be used to obtain a listing of the
remote web server directories even if they have a default 
page such as index.html.

This allows an attacker to gain valuable information about the
directory structure of the remote host and could reveal the
presence of files which are not intended to be visible.

Solution : disable the WebDAV module, or restrict its access to
authenticated and trusted clients.
Risk factor : Low";

  desc["francais"] = "
Il est possible d'obtenir la liste du contenu des repertoires
distants accessibles par HTTP, plutot que leur fichier index.html,
en utilisant le module WebDAV.

 Ce problème permet à un pirate d'obtenir plus d'informations
sur la machine attaquée, ainsi que de découvrir la présence de
fichiers HTML cachés.

Solution : désactivez le module WebDAV, ou restreignez son accès
aux utilisateurs authentifiés";

 script_description(english:desc["english"], francais:desc["francais"]);

 summary["english"] = "Checks the presence of WebDAV";
 summary["francais"] = "Vérifie la présence de WebDAV";
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
  soc = open_sock_tcp(port);
  if(soc)
  {
  quote = raw_string(0x22);
  req = string("PROPFIND / HTTP/1.1\r\n",
    	     "Host: ", get_host_name(), "\r\n",
	     "Content-Type: text/xml\r\n",
	     "Depth: 1\r\n",
	     "Content-Length: 110\r\n\r\n",
	     "<?xml version=", quote, "1.0", quote, "?>\r\n",
	     "<a:propfind xmlns:a=", quote, "DAV:", quote, ">\r\n",
	     " <a:prop>\r\n",
	     "  <a:displayname:/>\r\n",
	     " </a:prop>\r\n",
	     "</a:propfind>\r\n");

  send(socket:soc, data:req);
  result = recv_line(socket:soc, length:2048);
  r = http_recv(socket:soc);
  close(soc);
  if("HTTP/1.1 207 " >< result)
   {
    if("D:href" >< r)security_warning(port);
   }
  }
}
