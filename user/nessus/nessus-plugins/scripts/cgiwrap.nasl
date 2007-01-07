#
# This script was written by Mathieu Perrin <mathieu@tpfh.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10041);
 script_version ("$Revision: 1.15 $");
 script_bugtraq_id(777, 1238);
 script_cve_id("CVE-1999-1530", "CVE-2000-0431");


 name["english"] = "Cobalt RaQ2 cgiwrap";
 name["francais"] = "Cobalt RaQ2 cgiwrap";
 script_name(english:name["english"], francais:name["francais"]);

 desc["english"] = "'cgiwrap' is installed. This CGI has
 a well known security flaw that lets anyone execute arbitrary
 commands with the privileges of the http daemon (root or nobody).

*** Note that all versions of cgiwrap are not affected
*** by this problem ! Consult your vendor.
   
Solution :  remove it from /cgi-bin.

Risk factor : Serious";

desc["francais"] = "Le cgi 'cgiwrap' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de faire
executer des commandes arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody).

** Notez que toutes les versions de cgiwrap ne sont pas vulnérables
   consultez votre vendeur.
   
   
Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";



 script_description(english:desc["english"], francais:desc["francais"]);

 summary["english"] = "Checks for the presence of /cgi-bin/cgiwrap";
 summary["francais"] = "Vérifie la présence de /cgi-bin/cgiwrap";
   
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

port = is_cgi_installed("cgiwrap");
if(port)security_hole(port);

   
