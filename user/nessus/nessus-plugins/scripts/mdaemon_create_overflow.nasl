#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11577);
 script_bugtraq_id(7446);
 script_version ("$Revision: 1.1 $");
 
 
 name["english"] = "MDaemon IMAP CREATE overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to crash the remote MDaemon server by suppling 
an oversized argument to the CREATE imap command.

An attacker may use this flaw to prevent other users from
fetching their e-mail. It will also crash other MDaemon services
(SMTP, POP), thus preventing this server from receiving any email
as well, or even to execute arbitrary code on this host with the
privileges of the mdaemon IMAP daemon.

To exploit this flaw, a valid IMAP account is needed.

*** Nessus solely relied on the version number of the remote server
*** to issue this warning.

Solution : upgrade to MDaemon 6.7.10 or newer
Risk Factor : High";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Determines the version number of the remote IMAP server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/imap", 143);
 exit(0);
}

#
# The script code starts here
#



port = get_kb_item("Services/imap");
if(!port)port = 143;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 banner  = recv_line(socket:soc, length:4096);
 close(soc);
 
 if(ereg(pattern:".* IMAP.* MDaemon ([0-5]\.|6\.([0-6]\.|7\.[0-9][^0-9]))", string:banner))
 	security_hole(port);
}
