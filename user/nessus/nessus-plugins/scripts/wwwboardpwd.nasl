#
# This cgi abuse script was written by Jonathan Provencher
# Ce script de scanning de cgi a ete ecrit par Jonathan Provencher
# <druid@balistik.net>
#


if(description)
{
 script_id(10321);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-1999-0953");
 script_bugtraq_id(649);
 
 name["english"] = "wwwboard passwd.txt";
 name["francais"] = "wwwboard passwd.txt";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The file /wwwboard/passwd.txt exists.

 This file is installed by default with Matt's Script wwwboard
 software.  This can be a high risk vulnerability if the
 password used is the same for other services.  An attacker
 can easily take over the board by cracking the passwd.

Solution : Configure the wwwadmin.pl script to put
           the passwd.txt file somewhere else.

Risk factor : High";


 desc["francais"] = "
 Le fichier  /wwwboard/passwd.txt est présent.
 
 Ce fichier est installé par defaut par le 
 logiciel wwwboard de Matt's scripts.  Cela peut presenter un 
 risque enorme si le mot de passe utiliser et le meme pour 
 d'autres services.
 Un utilisateur malicieux peut facilement prendre controle
 du wwwboard en craquant facilement le fichier passwd.txt 

Solution : Configurer le script wwwadmin.pl pour
           relocaliser le fichier passwd.txt

Facteur de risque : Elevé";




 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /wwwboard/passwd.txt";
 summary["francais"] = "Vérifie la présence de /wwwboard/passwd.txt";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Jonathan Provencher",
		francais:"Ce script est Copyright (C) 1999 Jonathan Provencher"
	);	

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

cgi = "/wwwboard/passwd.txt";
port = is_cgi_installed(cgi);
if(port)security_hole(port);

