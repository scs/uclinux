#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10079);
 script_version ("$Revision: 1.31 $");
 script_cve_id("CAN-1999-0497");
 script_name(english:"Anonymous FTP enabled");
	     
 script_description(english:"
This FTP service allows anonymous logins. If you do not want to share data 
with anyone you do not know, then you should deactivate the anonymous account, 
since it can only cause troubles.

Risk factor : Low");
 
 script_summary(english:"Checks if the remote ftp server accepts anonymous logins");

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 script_dependencie("find_service.nes", "logins.nasl", "smtp_settings.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

state = get_port_state(port);
if(!state)exit(0);
soc = open_sock_tcp(port);
if(soc)
{
 domain = get_kb_item("Settings/third_party_domain");
 r = ftp_log_in(socket:soc, user:"anonymous", pass:string("nessus@", domain));
 if(r)
 {
  port2 = ftp_get_pasv_port(socket:soc);
  if(port2)
  {
   soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
   if (soc2)
   {
    send(socket:soc, data:'LIST /\r\n');
    listing = ftp_recv_listing(socket:soc2);
    close(soc2);
    }
  }
  
  data = "
This FTP service allows anonymous logins. If you do not want to share data 
with anyone you do not know, then you should deactivate the anonymous account, 
since it may only cause troubles.

";

  if(strlen(listing))
  {
   data += "The content of the remote FTP root is :
   
" + listing; 
  }
 
 data += "
 
Risk factor : Low";
 
  security_warning(port:port, data:data);
  set_kb_item(name:"ftp/anonymous", value:TRUE);
  user_password = get_kb_item("ftp/password");
  if(!user_password)
  {
   set_kb_item(name:"ftp/login", value:"anonymous");
   set_kb_item(name:"ftp/password", value:string("nessus@", domain));
  }
 }
 close(soc);
}


