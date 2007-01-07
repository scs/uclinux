#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(11300);
 script_version("$Revision: 1.4 $");
 script_cve_id("CAN-2002-0724");
 script_bugtraq_id(5556);
 
 name["english"] = "Unchecked buffer in Network Share Provider (Q326830)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is vulnerable to a denial of service attack,
which could allow an attacker to crash it by sending a specially
crafted SMB (Server Message Block) request to it.

Impact of vulnerability: Denial of Service / Elevation of Privilege 

Maximum Severity Rating: Moderate

Solution :  http://www.microsoft.com/technet/security/bulletin/ms02-045.asp

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q326830";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl",
		     "smb_reg_service_pack_XP.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_access","SMB/WindowsVersion");

 script_exclude_keys("SMB/XP/ServicePack");
 

 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;


access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");

if("5.0" >< version)
{
# fixed in Service Pack 4
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [4-9]"))exit(0);
}

if("5.1" >< version)
{
# fixed in Service Pack 1
 sp = get_kb_item("SMB/XP/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [1-9]"))exit(0);
}

# Win2003 and newer not vulnerable
if(ereg(pattern:"([6-9]\.[0-9])|(5\.[2-9])", string:version))exit(0);





key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q326830";
item = "Comments";
value = registry_get_sz(key:key, item:item);
if(!value)security_hole(port);
