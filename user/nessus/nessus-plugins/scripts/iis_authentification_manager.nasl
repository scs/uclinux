#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# 2002-06-07 [Michel Arboi]
# I added aexp3.htr and the comment about the locked account.
#

if(description)
{
 script_id(10371);
 script_version ("$Revision: 1.17 $");
 script_bugtraq_id(2110);
 script_cve_id("CVE-1999-0407", "CAN-2002-0421");

 name["english"] = "/iisadmpwd/aexp2.htr";
 name["francais"] = "/iisadmpwd/aexp2.htr";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The file /iisadmpwd/aexp2.htr is present.
(or, aexp2b.htr, aexp3.htr, or aexp4.htr, search for aexp*.htr)

An attacker may use it in a brute force attack
to gain valid username/password.
A valid user may also use it to change his password
on a locked account.

Solution : Delete the file
Risk factor : Serious";


 desc["francais"] = "
Le fichier /iisadmpwd/aexp2.htr est présent.

Ce fichier peut etre utilisé par des pirates
pour obtenir des mots de passes valides par
force brute.
Un utilisateur valide peut aussi l'utiliser 
pour changer le mot de passe d'un compte verrouillé.

Solution : effacez-le
Facteur de risque : Sérieux";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Determines whether /iisadmpwd/aexp2.htr is present";
 summary["francais"] = "Determines si /iisadmpwd/aexp2.htr est présent";
 
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
include("http_keepalive.inc");

function test_cgi(port, cgi, output)
{
 req = http_get(item:cgi, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if(output >< r)
  {
  	security_hole(port);
	exit(0);
  }
 return(0);
}
 
 


port = get_kb_item("Services/www");
if(!port)port = 80;
if(get_port_state(port))
{
  test_cgi(port:port, 
 	  cgi:"/iisadmpwd/aexp.htr",
	  output:"IIS - Authentication Manager");	  

  test_cgi(port:port, 
 	  cgi:"/iisadmpwd/aexp2.htr",
	  output:"IIS - Authentication Manager");	  
  test_cgi(port:port,
          cgi:"/iisadmpwd/aexp2b.htr",
          output:"IIS - Authentication Manager"); 
  test_cgi(port:port,
          cgi:"/iisadmpwd/aexp3.htr",
          output:"IIS - Authentication Manager");      
  test_cgi(port:port,
          cgi:"/iisadmpwd/aexp4.htr",
          output:"IIS - Authentication Manager");      

  test_cgi(port:port,
          cgi:"/iisadmpwd/aexp4b.htr",
          output:"IIS - Authentication Manager");      
}
	  
