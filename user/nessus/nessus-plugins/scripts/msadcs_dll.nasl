 
#
# Msadcs.dll locate.
#
# This plugin was written in NASL by RWT roelof@sensepost.com
#
# Changes by rd: 
# - french


if(description)
{
 script_id(10357);
 script_version ("$Revision: 1.13 $");
 script_bugtraq_id(529);
 script_cve_id("CVE-1999-1011");


 name["english"] = "RDS / MDAC Vulnerability (msadcs.dll) located";
 name["francais"] = "RDS / MDAC Vulnerability (msadcs.dll) possible";

  
 script_name(english:name["english"], francais:name["francais"], deutsch:name["deutsch"]);
 
 desc["english"] = "
The web server is probably susceptible to a common IIS vulnerability discovered by
'Rain Forest Puppy'. This vulnerability enables an attacker to execute arbitrary
commands on the server with Administrator Privileges. 

*** Nessus solely relied on the presence of the file /msadc/msadcs.dll
*** so this might be a false positive

See Microsoft security bulletin (MS99-025) for patch information.
Also, BUGTRAQ ID 529 on www.securityfocus.com ( http://www.securityfocus.com/bid/529 )

Risk factor : High";



 desc["francais"] = "Le script msadcs.dll a été trouvé dans /msadc/.
C'est un script de démo qui permet a des pirates
d'executer du code arbitraire sur le système
distant.

Solution : effacez-le
Facteur de risque : Elevé
Voir aussi : BUGTRAQ ID 529 on www.securityfocus.com ( http://www.securityfocus.com/bid/529 )";


 

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Determines the presence of msadcs.dll";
 summary["francais"] = "Vérifie la présence de /msadc/msadcs.dll";


 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Roelof Temmingh <roelof@sensepost.com>",
		francais:"Ce script est Copyright (C) 2000 Roelof Temmingh <roelof@sensepost.com>"
		);

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";

 script_family(english:family["english"], francais:family["francais"]);
 
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}

#
# The script code starts here
#


cgi = "/msadc/msadcs.dll";
port = is_cgi_installed(cgi);
if(port)security_hole(port);
