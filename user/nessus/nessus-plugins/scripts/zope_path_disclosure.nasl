#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# http://collector.zope.org/Zope/359
#

if(description)
{
 script_id(11234);
 script_version ("$Revision: 1.2 $");
 script_bugtraq_id(5806);
 #script_cve_id("");
 
 name["english"] = "Zope installation path disclose";
 name["francais"] = "Zope dévoile son répertoire d'installation";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote web server is Zope
There is a minor security problem in all releases of Zope
prior to version 2.5.1b1 which reveal the installation
path when an invalid XML RPC request is sent

http://collector.zope.org/Zope/359

Solution : Upgrade to Zope 2.5.1b1 or 2.6.0b1
Risk factor : Low";

 desc["francais"] = "
Le serveur web distant est Zope
Un problème de sécurité mineur affecte toutes les 
versions de Zope inférieures à 2.5.1b1 : elles révèlent
leur répertoire d'installation quand on envoie une
requête XML RPC invalide.

http://collector.zope.org/Zope/359

Solution : Mettez Zope à jour en version 2.5.1b1 ou 2.6.0b1
Facteur de risque : Faible";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for Zope installation directory";
 summary["francais"] = "Détecte le répertoire d'installation de Zope";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi",
		francais:"Ce script est Copyright (C) 2003 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/zope");
 exit(0);
}

# The script code starts here

include("http_func.inc");
port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);

s = http_open_socket(port);
if (! s) exit(0);

# The proof of concept request was:
# POST /Documentation/comp_tut HTTP/1.0
# Host: localhost
# Content-Type: text/xml
# Content-length: 93
# 
# <?xml version="1.0"?>
# <methodCall>
# <methodName>objectIds</methodName>
# <params/>
# </methodCall>
#
# but it does not seem to be necessary IIRC.

req = http_post(port: port, item: "/Foo/Bar/Nessus");
send(socket: s, data: req);
a = http_recv(socket: s);
if (egrep(string: a, 
         pattern: "(File|Bobo-Exception-File:) +(/[^/]*)*/[^/]+.py"))
  security_warning(port);
http_close_socket(s);
