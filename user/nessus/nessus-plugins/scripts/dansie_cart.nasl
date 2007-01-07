#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10368);
 script_version ("$Revision: 1.11 $");
 script_bugtraq_id(1115);
 script_cve_id("CVE-2000-0252");

 
 name["english"] = "Dansie Shopping Cart backdoor";
 name["francais"] = "Backdoor de Dansie Shopping Cart";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The script /cart/cart.cgi is present.

If this shopping cart system is the Dansie
Shopping Cart, and if it is older than version 3.0.8
then it is very likely that it contains a backdoor 
which allows anyone to execute arbitrary commands on this system.

Solution : use another cart system
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of Dansie Shopping Cart";
 summary["francais"] = "Détermine la présence de Dansie Shopping Cart";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

port = is_cgi_installed("/cart/cart.cgi");
if(port)security_hole(port);


