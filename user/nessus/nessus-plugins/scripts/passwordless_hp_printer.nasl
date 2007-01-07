#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10172);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CAN-1999-1061");

 name["english"] = "Passwordless HP LaserJet";
 name["francais"] = "HP Laserjet sans mot de passe";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote printer has no
password set. This allows anyone to change
its IP, thus to generate problems on your
network.

Solution : telnet to this printer and
set a password.

Risk factor : Serious";

 desc["francais"] = "L'imprimante distante
n'a pas de mot de passe. Cela permet à 
n'importe qui de changer son IP, 
générant ainsi des problèmes sur
votre réseau.

Solution : faites un telnet sur cette
imprimante et mettez un mot de passe.

Facteur de risque : Sérieux";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Notifies that the remote printer has no password";
 summary["francais"] = "Signale si l'imprimante distante n'a pas de mot de passe";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports(23);
 exit(0);
}

#
# The script code starts here
#

passwordless = 0;
port = 23;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = telnet_init(soc);
  if("JetDirect" >< buf){
  	set_kb_item(name:"devices/hp_printer", value:TRUE);
  	buf += recv(socket:soc, length:1024);
	buf = tolower(buf);
	if("password" >!< buf && "username" >!< buf)  passwordless = 1;
	}
 else {
  	buf += recv(socket:soc, length:1024, timeout:2);
	if("JetDirect" >< buf)
	{
	 set_kb_item(name:"devices/hp_printer", value:TRUE);
	 if("password" >!< buf && "username" >!< buf) passwordless = 1;
 	}
      }
   if ( passwordless ) {
   	security_hole(port);
	
	
# Send '/' to retrieve the current settings
        request = string ("/\r\n");
	send(socket:soc, data:request);
	info = recv(socket:soc, length: 1024);
	if ( "JetDirect" >< info ) {
		report = string ("It was possible to obtain the remote printer configuration:", info);
	} else {
		report = string ("The printer did not answer as expected when sending it '/':", info);
        }
	security_note(port:port, data:report);
  }
  close(soc);
 }
}
