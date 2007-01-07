#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Also covers:
# CAN-2002-0126
# CVE-2000-0870
# ezserver FTP overflow (tested -> crashes by sending a too long username)
#
# References:
# From: support@securiteam.com
# Subject: [NT] Hyperion FTP Server Buffer Overflow (dir)
# To: list@securiteam.com
# Date: 25 Dec 2002 11:08:39 +0200
#
# From: support@securiteam.com
# Subject: [NT] Multiple Vulnerabilities in Enceladus Server (cd, dir, mget)
# To: list@securiteam.com
# Date: 25 Dec 2002 11:03:42 +0200
#
# From:	"Carsten H. Eiram" <che@secunia.com>
# To: "Full Disclosure" <full-disclosure@lists.netsys.com>,
#    "VulnWatch" <vulnwatch@vulnwatch.org> 
# Date:	26 Jun 2003 17:00:57 +0200
# Subject: Secunia Research: FTPServer/X Response Buffer Overflow Vulnerability
# 
	


if(description)
{
 script_id(10084);
 script_version ("$Revision: 1.45 $");
 script_cve_id("CAN-2000-0133", "CVE-2000-0943", "CAN-2002-0126", "CVE-2000-0870", "CVE-2000-1035", "CVE-2000-1194", "CAN-2000-1035");
 script_bugtraq_id(961, 1858, 3884, 7251, 7278, 7307);

 name["english"] = "ftp USER, PASS or HELP overflow";
 name["francais"] = "dépassement de buffer avec les commandes USER, PASS ou HELP";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The remote FTP server closes
the connection when a command is too long or is given
a too long argument. 

This probably due to a buffer overflow, which
allows anyone to execute arbitrary code
on the remote host.

This problem is threatening, because
the attackers don't need an account 
to exploit this flaw.

Solution : Upgrade your FTP server or change it
Risk factor : High";


 desc["francais"] = "Le server FTP distant coupe
la connection lorsque l'une des commandes est accompagnée 
d'un argument trop long.

C'est probablement du à un dépassement de
buffer, ce qui permet à n'importe qui
d'executer du code arbitraire sur cette
machine.

Ce problème est grave, car les pirates
n'ont pas besoin d'avoir un accompte
sur le serveur FTP pour exploiter ce
probleme.

Solution : Mettez à jour votre serveur FTP
ou changez-le
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "attempts some buffer overflows";
 summary["francais"] = "essaye des buffers overflows";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl");
 script_exclude_keys("ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;



if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  d = ftp_recv_line(socket:soc);
  if(!d){
	set_kb_item(name:"ftp/false_ftp", value:TRUE);
	close(soc);
	exit(0);
	}
  if(!ereg(pattern:"^220 ", string:d))
   {
    # not a FTP server
    set_kb_item(name:"ftp/false_ftp", value:TRUE);
    close(soc);
    exit(0);	
   }
 
  if("Microsoft FTP service" >< d)exit(0);
 
  req = string("USER ftp\r\n");
  send(socket:soc, data:req);
  d = ftp_recv_line(socket:soc);
  ftp_close(socket:soc);
  if(!d)
  {
   set_kb_item(name:"ftp/false_ftp", value:TRUE);
   exit(0);	
  }
  
  soc = open_sock_tcp(port);
  d = ftp_recv_line(socket:soc);
  s = string("USER ", crap(4096), "\r\n");
  send(socket:soc, data:s);
  d = ftp_recv_line(socket:soc);
  if(!d){
  	set_kb_item(name:"ftp/overflow", value:TRUE);
	set_kb_item(name:"ftp/overflow_method", value:"USER");
	security_hole(port);
	}
  else
  {
   s = string("USER nessus\r\n");
   send(socket:soc, data:s);
   d = ftp_recv_line(socket:soc);
   s = string("PASS ", crap(4096), "\r\n");
   send(socket:soc, data:s);
   d = ftp_recv_line(socket:soc);
   if(!d){
  	set_kb_item(name:"ftp/overflow", value:TRUE);
	set_kb_item(name:"ftp/overflow_method", value:"PASS");
	security_hole(port);
	}
   else
   {
     s = string("CWD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
  	set_kb_item(name:"ftp/overflow", value:TRUE);
	set_kb_item(name:"ftp/overflow_method", value:"CWD");
	security_hole(port);
	exit(0);
	}
	
     s = string("LIST ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
  	set_kb_item(name:"ftp/overflow", value:TRUE);
	set_kb_item(name:"ftp/overflow_method", value:"LIST");
	security_hole(port);
	exit(0);
	}
	
		
     s = string("STOR ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
  	set_kb_item(name:"ftp/overflow", value:TRUE);
	set_kb_item(name:"ftp/overflow_method", value:"STOR");
	security_hole(port);
	exit(0);
	}
	
     s = string("RNTO ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
  	set_kb_item(name:"ftp/overflow", value:TRUE);
	set_kb_item(name:"ftp/overflow_method", value:"RNTO");
	security_hole(port);
	exit(0);
	}
	
     s = string("MKD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
  	set_kb_item(name:"ftp/overflow", value:TRUE);
	set_kb_item(name:"ftp/overflow_method", value:"MKD");
	security_hole(port);
	exit(0);
	}	
		
     s = string("XMKD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
  	set_kb_item(name:"ftp/overflow", value:TRUE);
	set_kb_item(name:"ftp/overflow_method", value:"XMKD");
	security_hole(port);
	exit(0);
	}
	
     s = string("RMD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
  	set_kb_item(name:"ftp/overflow", value:TRUE);
	set_kb_item(name:"ftp/overflow_method", value:"RMD");
	security_hole(port);
	exit(0);
	}	


     s = string("XRMD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
  	set_kb_item(name:"ftp/overflow", value:TRUE);
	set_kb_item(name:"ftp/overflow_method", value:"XRMD");
	security_hole(port);
	exit(0);
	}	
	
     s = string("APPE ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
  	set_kb_item(name:"ftp/overflow", value:TRUE);
	set_kb_item(name:"ftp/overflow_method", value:"APPE");
	security_hole(port);
	exit(0);
	}
	
     s = string("SIZE ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
  	set_kb_item(name:"ftp/overflow", value:TRUE);
	set_kb_item(name:"ftp/overflow_method", value:"SIZE");
	security_hole(port);
	exit(0);
	}
	
     s = string("RNFR ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
  	set_kb_item(name:"ftp/overflow", value:TRUE);
	set_kb_item(name:"ftp/overflow_method", value:"RNFR");
	security_hole(port);
	exit(0);
	}
	
				
     s = string("HELP ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
  	set_kb_item(name:"ftp/overflow", value:TRUE);
	set_kb_item(name:"ftp/overflow_method", value:"HELP");
	security_hole(port);
	exit(0);
	}

     s = string(crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
  	set_kb_item(name:"ftp/overflow", value:TRUE);
	set_kb_item(name:"ftp/overflow_method", value:"");
	security_hole(port);
	exit(0);
	}
     }
    }
   close(soc);
  }
 }
