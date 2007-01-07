#
# (C) Tenable Network Security
#
# Ref:
#  Date: Wed, 18 Jun 2003 21:58:51 +0200 (CEST)
#  Subject: Multiple buffer overflows and XSS in Kerio MailServer
#  From: "David F.Madrid" <conde0@telefonica.net>
#  To: <bugtraq@securityfocus.com>


if(description)
{
 script_id(11763);
 script_bugtraq_id(7966, 7967, 7968);
 script_version ("$Revision: 1.3 $");

 name["english"] = "Kerio WebMail interface flaws";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running version 5 of the Kerio WebMail interface.

There are multiple flaws in this interface which may allow
an attacker with a valid webmail account on this host 
to obtain a shell on this host or to perform
a cross-site-scripting attack against this host.

*** This might be a false positive, as Nessus did not have
*** the proper credentials to determine if the remote Kerio
*** is affected by this flaw.

Solution : Upgrade to Kerio MailServer 5.6.3 or newer
Risk Factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Kerio MailServer";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_kb_item("Services/www");
if(!port) port = 80;

if(!get_port_state(port))exit(0);

req = http_get(item:"/login", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if("<title>Webmail | Kerio MailServer 5</title>" >< res)
{
 security_warning(port);
}
