#
# written by Renaud Deraison <deraison@cvs.nessus.org>
#


if(description)
{
 script_id(11485);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CAN-2002-1561");
 
 name["english"] = "Flaw in RPC Endpoint Mapper (MS03-010)";

 script_name(english:name["english"]);
 
 desc["english"] = "
A flaw exists in the RPC endpoint mapper, which can be used by an attacker
to disable it remotely.

An attacker may use this flaw to prevent this host from working
properly


Affected Software:

Microsoft Windows NT 4
Microsoft Windows 2000
Microsoft Windows XP

Solution for Win2k and XP: see
http://www.microsoft.com/technet/security/bulletin/ms03-010.asp

There is no patch for NT4.

Microsoft strongly recommends that customers still using
Windows NT 4.0 protect those systems by placing them behind a
firewall which is filtering traffic on Port 135.

Risk factor : Serious";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q331953";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/WindowsVersion",
		     "SMB/registry_access");
 script_require_ports(445, 139);
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");


if("4.0" >< version)
{
 # Microsoft does not intend to release a patch. They are so understaffed
 # that we can understand this very well.
 security_hole(port);
}

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q331953";
item = "Comments";
value = registry_get_sz(key:key, item:item);

if("5.0" >< version)
{
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(pattern:"Service Pack [4-9]", string:sp))exit(0);
 if(!value)security_hole(port);
}

if("5.1" >< version)
{
 sp = get_kb_item("SMB/XP/ServicePack");
 if(ereg(pattern:"Service Pack [2-9]", string:sp))exit(0);
 if(!value)security_hole(port);
}

