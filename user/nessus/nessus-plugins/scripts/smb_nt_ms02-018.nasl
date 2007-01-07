#
# This script was written by Michael Scheidell <scheidell at secnap.net>
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(10943);
 script_cve_id("CVE-2002-0147", "CVE-2002-0149",
 	       "CVE-2002-0150", "CAN-2002-0224",
 	       "CAN-2002-0869", "CAN-2002-1182",
	       "CAN-2002-1180", "CAN-2002-1181");
 script_bugtraq_id(4474);
 script_version("$Revision: 1.13 $");
 name["english"] = "Cumulative Patch for Internet Information Services (Q327696)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Cumulative Patch for Microsoft IIS (Q327696)

Impact of vulnerability: Ten new vulnerabilities, the most
serious of which could enable code of an attacker's choice
to be run on a server.

Recommendation: Users using any of the affected
products should install the patch immediately.

Maximum Severity Rating: Critical 

Affected Software: 

Microsoft Internet Information Server 4.0 
Microsoft Internet Information Services 5.0 
Microsoft Internet Information Services 5.1 

See
http://www.microsoft.com/technet/security/bulletin/ms02-062.asp

Supersedes

http://www.microsoft.com/technet/security/bulletin/ms02-018.asp

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether October 30, 2002 IIS Cumulative patches (Q327696) are installed";

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

key = "SYSTEM\CurrentControlSet\Services\W3SVC";
item = "ImagePath";

value = registry_get_sz(key:key, item:item);
if(!value)exit(0); # No IIS installed
if("inetinfo" >!< value)exit(0); # Not IIS

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q327696";
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

