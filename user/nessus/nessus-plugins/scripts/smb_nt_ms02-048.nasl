#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(11144);
 script_version("$Revision: 1.3 $");
 script_cve_id("CAN-2002-0699");
 name["english"] = "Flaw in Certificate Enrollment Control (Q323172)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
A vulnerability in the Certificate Enrollment
ActiveX Control in Microsoft Windows 98, Windows 98
Second Edition, Windows Millennium, Windows NT 4.0,
Windows 2000, and Windows XP allows remote attackers
to delete digital certificates on a user's system
via HTML.

Impact of vulnerability: Denial of service 

Maximum Severity Rating: Critical 

Recommendation: Customers should install the patch immediately 

Affected Software: 

Microsoft Windows 98 
Microsoft Windows 98 Second Edition 
Microsoft Windows Millennium 
Microsoft Windows NT 4.0 
Microsoft Windows 2000 
Microsoft Windows XP 

See
http://www.microsoft.com/technet/security/bulletin/ms02-048.asp

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q323172, Certificate Enrollment Flaw";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 SECNAP Network Security, LLC");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl",
		     "smb_reg_service_pack_XP.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/WindowsVersion",
		     "SMB/registry_access");
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

if(ereg(pattern:"([6-9]\.[0-9])|(5\.[2-9])", string:version))exit(0);

if("5.0" >< version)
{
# fixed in Service Pack 4
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [4-9]"))exit(0);
}
 
if("5.1" >< version)
{
# fixed in SP 1
 sp = get_kb_item("SMB/XP/ServicePack");
 if(sp)exit(0);
}
#assume winnt 4.0 or not high enough service pack

 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Hotfix\Q323172";
# note : despite the microsoft web site, win2k DOES update this reg,
# and it is safer to check, only needs user privs
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);

