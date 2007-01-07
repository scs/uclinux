#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10389);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CAN-2000-0429");
 script_bugtraq_id(1153);
 
 name["english"] = "Cart32 ChangeAdminPassword";
 name["francais"] = "Cart32 ChangeAdminPassword";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The Cart32 e-commerce shopping cart is installed.

This software contains several security flaws :

	- it may contain a backdoor
	- users may be able to change the admin password remotely


You should use something else.

See also : http://www.cerberus-infosec.co.uk/advcart32.html

Solution : use another shopping cart software
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of Cart32";
 summary["francais"] = "Détermine la présence de Cart32";
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

port = is_cgi_installed("c32web.exe/ChangeAdminPassword");
if(port)security_hole(port);
