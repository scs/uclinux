#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(11029);
 script_version("$Revision: 1.8 $");
 script_bugtraq_id(4852);
 script_cve_id("CVE-2002-0366");
 name["english"] = "Windows RAS overflow (Q318138)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
An overflow in the RAS phonebook service allows a local user
to execute code on the system with the privileges of LocalSystem.

Impact of vulnerability: Elevation of Privilege 

Affected Software: 

Microsoft Windows NT 4.0 
Microsoft Windows NT 4.0 Server, Terminal Server Edition 
Microsoft Windows 2000 
Microsoft Windows XP

Recommendation: Users using any of the affected
products should install the patch immediately.

Maximum Severity Rating: Critical (locally)

See
http://www.microsoft.com/technet/security/bulletin/ms02-029.asp

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q318138, Elevated Privilege";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl",
		     "smb_reg_service_pack.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_access","SMB/WindowsVersion");
 script_exclude_keys("SMB/XP/ServicePack");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;

version = get_kb_item("SMB/WindowsVersion");


if(ereg(pattern:"([6-9]\.[0-9])|(5\.[2-9])", string:version))exit(0);


if("5.0" >< version)
{
# fixed in Service Pack 3
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [3-9]"))exit(0);
}

if("5.1" >< version)
{
 # fixed in SP1
 sp = get_kb_item("SMB/XP/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [1-9]"))exit(0);
}


key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q318138";
item = "Comments";
value = registry_get_sz(key:key, item:item);
if(!value)security_hole(port);
