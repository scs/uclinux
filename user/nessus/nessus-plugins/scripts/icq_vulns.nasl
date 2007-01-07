#
# This script was written by Renaud Deraison <rderaison@tenablesecurity.com>
#
# See the Nessus Scripts License for details
#
# Ref: 
# Date: Mon, 05 May 2003 16:44:47 -0300
# From: CORE Security Technologies Advisories <advisories@coresecurity.com>
# To: Bugtraq <bugtraq@securityfocus.com>,
# Subject: CORE-2003-0303: Multiple Vulnerabilities in Mirabilis ICQ client
#

if(description)
{
 script_id(11572);
 script_version("$Revision: 1.1 $");
 script_cve_id("CAN-2003-0235", "CAN-2003-0236", "CAN-2003-0237", "CAN-2003-0238", "CAN-2003-0239");
 script_bugtraq_id(7461, 7462, 7463, 7464, 7465, 7466);
 name["english"] = "Multiple ICQ Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using ICQ - an instant messenging client utility.

There are multiple flaws in all versions of ICQ which may allow an attacker
to execute arbitrary code on this host.

To exploit this flaw, an attacker would need to send a malformed e-mail 
to the ICQ user, or have it download its mail on a rogue POP3 server.

Solution : None at this time
Risk Factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if ICQ is installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/domain","SMB/transport");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_nt.inc");


rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\CurrentVersion\Uninstall\ICQ", item:"DisplayName");
if(rootfile)
{
 security_note(get_kb_item("SMB/transport"));
 exit(0); 
}

rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\CurrentVersion\Uninstall\ICQLite", item:"DisplayName");
if(rootfile)
{
 security_note(get_kb_item("SMB/transport"));
 exit(0); 
}


