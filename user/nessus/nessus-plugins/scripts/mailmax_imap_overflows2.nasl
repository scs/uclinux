#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
#  Date: Sat, 17 May 2003 14:31:14 +0200 
#  From: 0x36 <release@0x36.org>
#  To: bugtraq@securityfocus.com
#  Subject: Buffer overflow vulnerability found in MailMax version 5



if(description)
{
 script_id(11637);
 script_bugtraq_id(7327);
 script_version ("$Revision: 1.2 $");

 
 name["english"] = "MailMax IMAP overflows (2)";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the MailMax 
IMAP server which, according to its version number,
is vulnerable to various overflows which may allow an 
authenticated user to execute arbitrary commands on this 
host or to disable it remotely.

*** Nessus only checked the banner of this host, so
*** this might be a false positive

Solution : Upgrade to MailMax 5.5 or newer
Risk Factor : Serious";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of the remote IMAP server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/imap", 143);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/imap");
if(!port)port = 143;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  r = recv_line(socket:soc, length:4096);
  if(egrep(pattern:"MailMax [1-5][^0-9]", string:r))
   {
  security_hole(port);
   }
 }
}
