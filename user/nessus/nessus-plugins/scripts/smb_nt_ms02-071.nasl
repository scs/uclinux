#
# This script was written by Michael Scheidell <scheidell at secnap.net>
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(11191);
 script_version("$Revision: 1.6 $");
 script_cve_id("CAN-2002-1230");
 script_bugtraq_id(5927);
 name["english"] = "WM_TIMER Message Handler Privilege Elevation (Q328310)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
A security issue has been identified in WM_TIMER that
could allow an attacker to compromise a computer running 
Microsoft Windows and gain complete control over it.

Recommendation: Users using any of the affected
products should install the patch immediately.

Maximum Severity Rating: Critical 

Affected Software: 

Microsoft Windows NT 4.0 
Microsoft Windows NT 4.0, Terminal Server Edition 
Microsoft Windows 2000 
Microsoft Windows XP 

See
http://www.microsoft.com/technet/security/bulletin/ms02-071.asp

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks Registry for WM_TIMER Privilege Elevation Hotfix (Q328310)";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michael Scheidell");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl",
		     "smb_reg_service_pack.nasl",
		     "smb_reg_service_pack_W2K.nasl",
		     "smb_reg_service_pack_XP.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_access","SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");
if(ereg(pattern:"([6-9]\.[0-9])|(5\.[2-9])", string:version))exit(0);


key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q328310";
item = "Comments";

if("4.0" >< version)
{
 value = registry_get_sz(key:key, item:item);
 if(!value){
 	security_hole(port);
	}
 exit(0);
}


if("5.0" >< version)
{
# fixed in Service Pack 4
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [4-9]"))exit(0);
}

if("5.1" >< version)
{
 # fixed in XP service Pack 2
 sp = get_kb_item("SMB/XP/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [2-9]"))exit(0);
}

 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);

