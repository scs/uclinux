#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10263);
 script_version ("$Revision: 1.34 $");
 
 name["english"] = "SMTP Server type and version";
 script_name(english:name["english"]);
 
 desc["english"] = "This detects the SMTP Server's type and version by connecting to the server
and processing the buffer received.
This information gives potential attackers additional information about the
system they are attacking. Versions and Types should be omitted
where possible.

Solution: Change the login banner to something generic.

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "SMTP Server type and version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#
include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if (!port) port = 25;

if (get_port_state(port))
{
 soctcp25 = open_sock_tcp(port);

 if (soctcp25)
 {
  bannertxt = smtp_recv_banner(socket:soctcp25);

  if(!bannertxt){
        set_kb_item(name:"SMTP/wrapped", value:TRUE);
        close(soctcp25);
        exit(0);
        }

  if( ! ("220" >< bannertxt)) {
		# Doesn't look like SMTP...
		close(soctcp25);
		exit(0);
  }

  send(socket:soctcp25, data:string("EHLO ",this_host(),"\r\n"));
  ehlotxt = smtp_recv_line(socket:soctcp25);
  send(socket: soctcp25, data:string("HELP\r\n"));
  helptxt = smtp_recv_line(socket:soctcp25);
  send(socket: soctcp25, data:string("NOOP\r\n"));
  nooptxt = smtp_recv_line(socket:soctcp25);
  send(socket: soctcp25, data:string("RSET\r\n"));
  rsettxt = smtp_recv_line(socket:soctcp25);
  send(socket: soctcp25, data:string("QUIT\r\n"));
  quittxt = smtp_recv_line(socket:soctcp25);

  #display("banner=[",bannertxt,"]\nehlo=[",ehlotxt,"]\nhelp=[",helptxt,"]\nnoop=[",nooptxt,"]\nrset=[",rsettxt,"]\nquit=[",quittxt,"]\n");

  if (("Exim" >< bannertxt) ||
      (("closing connection" >< quittxt) && ("OK" >< nooptxt) && ("Commands supported:" >< helptxt)))
  {
   set_kb_item(name:"SMTP/exim", value:TRUE);
   guess = "Exim";
   str = egrep(pattern:" Exim ", string:bannertxt);
   if(str) {
     str=ereg_replace(pattern:"^.*Exim ([0-9\.]+) .*$", string:str, replace:"\1");
     guess=string("Exim version ",str);
   }
  }

  if (("qmail" >< bannertxt) || ("qmail" >< helptxt))
  {
   set_kb_item(name:"SMTP/qmail", value:TRUE);
   guess = "Qmail";
  }
  
  if ("Postfix" >< bannertxt)
  {
   set_kb_item(name:"SMTP/postfix", value:TRUE);
   guess = "Postfix";
  }
  
  if(("Sendmail" >< bannertxt) || ("This is sendmail version" >< helptxt) || ("sendmail-bugs@sendmail.org" >< helptxt))
  {
   set_kb_item(name:"SMTP/sendmail", value:TRUE);
   guess = "Sendmail";
   str = egrep(pattern:"This is sendmail version ", string:helptxt);
   if(str) {
     str=ereg_replace(pattern:".*This is sendmail version ", string:str, replace:"");
     guess=string("Sendmail version ",str);
   }
  }
  
  if("XMail " >< bannertxt)
  {
   set_kb_item(name:"SMTP/xmail", value:TRUE);
   guess = "XMail";
  }
  
  if(egrep(pattern:".*nbx.*Service ready.*", string:bannertxt))
  {
   set_kb_item(name:"SMTP/3comnbx", value: TRUE);
  }
  
  if(("Microsoft Exchange Internet Mail Service" >< bannertxt) ||
     ("NTLM LOGIN" >< bannertxt) ||
     ("Microsoft ESMTP MAIL Service, Version: 5" >< bannertxt) ||
     ("Microsoft SMTP MAIL" >< bannertxt) ||
     (("This server supports the following commands" >< helptxt) && ("End of HELP information" >< helptxt) &&
     ("Service closing transmission channel" >< quittxt) && ("Resetting" >< rsettxt)))
  {
   set_kb_item(name:"SMTP/microsoft_esmtp_5", value:TRUE);
   guess = "Microsoft Exchange version 5.X";
   str = egrep(pattern:" Version: ", string:bannertxt);
   if(str) {
     str=ereg_replace(pattern:".* Version: ", string:str, replace:"");
     guess=string("Microsoft Exchange version ",str);
   }
  }

  if(("ZMailer Server" >< bannertxt) ||
    (("This mail-server is at Yoyodyne Propulsion Inc." >< helptxt) && # Default help text.
     ("Out" >< quittxt) && ("zmhacks@nic.funet.fi" >< helptxt))) {
   set_kb_item(name:"SMTP/zmailer", value:TRUE);
   guess = "ZMailer";
   str = egrep(pattern:" ZMailer ", string:bannertxt);
   if(str) {
     str=ereg_replace(pattern:"^.*ZMailer Server ([0-9a-z\.\-]+) .*$", string:str, replace:"\1");
     guess=string("ZMailer version ",str);
   }
  }

  if("CheckPoint FireWall-1" >< bannertxt)
  {
   set_kb_item(name:"SMTP/firewall-1", value: TRUE);
   guess="CheckPoint FireWall-1";
  }

  if(("InterMail" >< bannertxt) ||
    (("This SMTP server is a part of the InterMail E-mail system" >< helptxt) &&
    ("Ok resetting state." >< rsettxt) && ("ESMTP server closing connection." >< quittxt))) {
   set_kb_item(name:"SMTP/intermail", value:TRUE);
   guess = "InterMail";
   str = egrep(pattern:"InterMail ", string:bannertxt);
   if(str) {
     str=ereg_replace(pattern:"^.*InterMail ([A-Za-z0-9\.\-]+).*$", string:str, replace:"\1");
     guess=string("InterMail version ",str);
   }
  }
 
  if(("Lotus Domino" >< bannertxt) ||
    (("pleased to meet you" >< ehlotxt) && ("Enter one of the following commands" >< helptxt) &&
    ("Reset state" >< rsettxt) && ("SMTP Service closing transmission channel" >< quittxt))) {
   set_kb_item(name:"SMTP/domino", value:TRUE);
   guess = "Domino";
   str = egrep(pattern:"Lotus Domino ", string:bannertxt);
   if(str) {
     str=ereg_replace(pattern:"^.*\(Lotus Domino Release ([0-9\.\-]+)\).*$", string:str, replace:"\1");
     guess=string("Lotus Domino version ",str);
   }
  }
 
  if (	"mail rejector" >< bannertxt ||
	match(pattern: "*snubby*", string: ehlotxt, icase: 1))
  {
    set_kb_item(name: "SMTP/snubby", value: TRUE);
    set_kb_item(name: "SMTP/wrapped", value: TRUE);
    guess = "Snubby Mail Rejector (not a real server)";
    security_note(port: port, data: "
Verisign mail rejector appears to be running on this port.
You probably mistyped your hostname and Nessus is scanning the wildcard
address in the .COM or .NET domain.

Solution : enter a correct hostname
Risk factor : none");
  }

  data = string("Remote SMTP server banner :\n",  bannertxt);
  if (guess) {
   data=string(data, "\n\n\nThis is probably: ",guess);
  }
  security_note(port:port, data:data);
 }

 close(soctcp25);
}
