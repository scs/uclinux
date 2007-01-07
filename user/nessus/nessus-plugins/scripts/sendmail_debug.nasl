#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10247);
 script_version ("$Revision: 1.14 $");
 script_bugtraq_id(1);
 script_cve_id("CVE-1999-0095");
 
 name["english"] = "Sendmail DEBUG";
 name["francais"] = "Sendmail DEBUG";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
Your MTA accepts the DEBUG mode.

This mode is dangerous as it allows remote
users to execute arbitrary commands as root
without the need to log in.

Solution : Upgrade your MTA.

Risk factor : High"; 
	

 desc["francais"] = "
Votre MTA accepte le mode DEBUG.

Ce mode est dangereux puisqu'il permet à 
des utilisateurs distants d'executer des
commandes arbitraires en tant que root
sur ce système, sans avoir à se logger.


Solution : Mettez à jour votre MTA.

Facteur de risque : Elevé";

 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Checks for the presence of the DEBUG mode"; 
 summary["francais"] = "Vérifie la présence du mode DEBUG";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "smtpserver_detect.nasl");
 script_require_keys("SMTP/sendmail");
 script_exclude_keys("SMTP/wrapped");

 script_require_ports("Services/smtp", 25);
 
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if(!get_port_state(port))exit(0);
if(get_kb_item("SMTP/wrapped"))exit(0);

soc = open_sock_tcp(port);
if(soc)
 {
  b = smtp_recv_banner(socket:soc);

  s = string("debug\r\n");
  send(socket:soc, data:s);
  r = recv_line(socket:soc, length:1024);
  r = tolower(r);

  
  if(("200 debug set" >< r))security_hole(port);
  close(soc);
}
