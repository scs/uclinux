#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10292);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-1999-0005");
 script_bugtraq_id(130);
 
 name["english"] = "uw-imap buffer overflow";
 name["francais"] = "Dépassement de buffer dans uw-imap";
 script_name(english:name["english"],
 	     francais:name["francais"]);
	     
 
 desc["english"] = "A buffer overflow in uw-imap allows a remote user to
become root easily. 

The overflow occurs when the user
issues a too long argument in the AUTHENTICATE
command.

Risk factor : High

Solution : Upgrade your uw-imap server to the newest version.";
 
 desc["francais"] = "Un dépassement de buffer dans uw-imap permet à 
un utilisateur distant de devenir root 
facilement.

Le dépassement survient lorsque l'utilisateur
donne un argument trop long à la commande
AUTHENTICATE.

Facteur de risque : Elevé

Solution : Mettez à jour votre serveur uw-imap.";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
		    
 
 summary["english"] = "uw-imap buffer overflow"; 
 summary["francais"] = "Dépassement de buffer dans uw-imap";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed

 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 	 	  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 
 script_family(english:family["english"],
 	       francais:family["francais"]);
	       
 script_dependencie("find_service.nes", "imap_overflow.nasl");
 script_exclude_keys("imap/false_imap");
 script_require_ports("Services/imap", 143);
 exit(0);
}

#
# The script code starts here
#


port = get_kb_item("Services/imap");
if(!port)port = 143;

if(safe_checks())
{
 banner = get_kb_item(string("imap/banner/", port));
 if(!banner)
 {
  if(get_port_state(port))
  { 
   soc = open_sock_tcp(port);
   if(!soc)exit(0);
   banner = recv_line(socket:soc, length:4096);
   close(soc);
  }
 }
 
 if(banner)
 {
  if((ereg(pattern:"OK .* IMAP v.* server ready",
          string:banner))||
     (ereg(pattern:"OK .* IMAP2bis .*",
           string:banner)))	
	  {
	   alrt = "
If the remote IMAP server is uw-imap, make
sure that you are running the latest version,
as older versions are vulnerable to a buffer
overflow in the AUTHENTICATE command.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : Upgrade
Risk factor : High";

	 security_warning(port:port,data:alrt);	   
	  }
 }
 exit(0);
}

if(get_port_state(port))
{
 data = string("* AUTHENTICATE {4096}\r\n", crap(4096), "\r\n");
 soc = open_sock_tcp(port);
 if(soc > 0)
 {
  buf = recv_line(socket:soc, length:1024);
 if(!strlen(buf))
 	{ 
	 	close(soc);
		exit(0);
	}
  send(socket:soc, data:data);
  buf = recv_line(socket:soc, length:1024);
  if(!strlen(buf)){
  	security_hole(port);
	set_kb_item(name:"imap/overflow", value:TRUE);
	}
  close(soc);
 }
}
