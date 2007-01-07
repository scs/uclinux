#
# This script was written by Michael Scheidell <scheidell at secnap.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10865);
 script_version("$Revision: 1.13 $");
 script_cve_id("CAN-2002-0053");
 name["english"] = "Checks for MS HOTFIX for snmp buffer overruns";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
There is an Unchecked Buffer in SNMP Service 
and this checks to see if the Microsoft Patch
has been applied (only checks NT/Win2k and XP PRo).

Impact of vulnerability: Run code of attacker's choice
and denial of service attacks.

Also may run snmp detect to see if snmp is running on this host.

Recommendation: Customers should install the patch immediately
or disable snmp (you should disable all unused services)

Affected Software: 

Microsoft Windows 95 
Microsoft Windows 98 
Microsoft Windows 98SE 
Microsoft Windows NT 4.0 
Microsoft Windows NT 4.0 Server, Terminal Server Edition 
Microsoft Windows 2000 
Microsoft Windows XP 

See http://www.microsoft.com/technet/security/bulletin/ms02-006.asp
(note about risk factor:
  Medium if not running snmp - because someone could enable it
  High if not patched and running snmp)

Risk factor : Medium/High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the hotfix Q314147 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michael Scheidell");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl",
 		     "smb_reg_service_pack.nasl",
		     "smb_reg_service_pack_W2K.nasl",
		     "smb_reg_service_pack_XP.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/registry_access");
 script_require_ports(139, 445);
 script_require_keys("SMB/WindowsVersion");
 script_exclude_keys("SMB/XP/ServicePack");
 exit(0);
}

include("smb_nt.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;


access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");
if(!version)exit(0);

if(version == "5.0")
{
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [3-9]"))exit(0);
}
if(version == "5.1")
{
 sp = get_kb_item("SMB/XP/ServicePack");
 if(sp)exit(0);
}

if(ereg(pattern:"([6-9]\.[0-9])|(5\.[2-9])", string:version))exit(0);
 
## default: Winnt, and xp,win2k (yes, undocumented but there)
key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q314147";
item = "Comments";

value = registry_get_sz(key:key, item:item);

if(!value)
 {
    report = "
The hotfix for the Unchecked Buffer in SNMP Service 
has not been applied.

Impact of vulnerability: Run code of attacker's choice
and denial of service attacks.

Recommendation: Customers should install the patch immediately
or disable snmp (you should disable all unused services)

See http://www.microsoft.com/technet/security/bulletin/ms02-006.asp

Risk factor : High";
   security_hole(port:port,data:report);
}
