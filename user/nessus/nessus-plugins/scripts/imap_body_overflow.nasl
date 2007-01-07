#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10966);
 script_cve_id("CVE-2002-0379");
 script_bugtraq_id(4713);
 script_version ("$Revision: 1.8 $");
 
 
 name["english"] = "IMAP4buffer overflow in the BODY command";

 
 script_name(english:name["english"]);
 
 desc["english"] = "
There is a buffer overflow in the remote imap server 
which allows an authenticated user to obtain a remote
shell.

By supplying an overly long tag the the BODY command,
an attacker may gain a shell on this host.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : Upgrade to imap-2001a
Risk factor : Serious";


 script_description(english:desc["english"]);
 
 summary["english"] = "checks for a buffer overflow in imapd";
 summary["francais"] = "vérifie la présence d'un dépassement de buffer dans imapd";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 # can be changed to MIXED when real attack tried.
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"],
	       francais:family["francais"]); 
 script_dependencie("find_service.nes", "logins.nasl");
		       		     
 script_require_ports("Services/imap", 143);
 script_exclude_keys("imap/false_imap");
 exit(0);
}


port = get_kb_item("Services/imap");
if(!port)port = 143;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

r = recv_line(socket:soc, length:4096);
if(!ereg(pattern:"OK .* IMAP4rev1 *200[01]\.[0-9][^ ]* at", string:r))exit(0);

#
# We check for this flaw the "clean way". In the future,
# this plugin might be modified to actually check for
# the flaw, but I feel lazy today
# sample sploit for Linux at:
# http://downloads.securityfocus.com/vulnerabilities/exploits/uw-imap.c
#
# 
send(socket:soc, data:string("x capability\r\n"));
r = recv_line(socket:soc, length:4096);

# According to the UW guys, if the server replies with IMAP4 and IMAP4REV1
# then it's vulnerable to the overflow.
if(ereg(pattern:".*CAPABILITY IMAP4 IMAP4REV1.*", string:r))
	security_hole(port);
