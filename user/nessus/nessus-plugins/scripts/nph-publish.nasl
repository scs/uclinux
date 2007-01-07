#
# This script was written by Mathieu Perrin <mathieu@tpfh.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10164);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-1999-1177", "CVE-2001-0400");
 
 name["english"] = "nph-publish.cgi";
 name["francais"] = "nph-publish.cgi";
 script_name(english:name["english"], francais:name["francais"]);

 desc["english"] = "The 'nph-publish.cgi' is installed. This CGI has
 a well known security flaw that lets an attacker to execute arbitrary
 commands with the privileges of the http daemon (usually root or nobody).

Solution :  remove it from /cgi-bin.

Risk factor : Serious";

desc["francais"] = "Le cgi 'nph-publish.cgi' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de faire
executer des commandes arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody).

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";



 script_description(english:desc["english"], francais:desc["francais"]);

 summary["english"] = "Checks for the presence of /cgi-bin/nph-publish.cgi";
 summary["francais"] = "Vérifie la présence de /cgi-bin/nph-publish.cgi";
   
 script_summary(english:summary["english"], francais:summary["francais"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 1999 Mathieu Perrin",
         francais:"Ce script est Copyright (C) 1999 Mathieu Perrin");

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

port = is_cgi_installed("nph-publish.cgi");
if(port)security_hole(port);
