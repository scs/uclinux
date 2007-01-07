#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details

if(description)
{
 script_id(11177);
 script_version("$Revision: 1.5 $");
 script_cve_id("CAN-2002-1257","CAN-2002-1258","CAN-2002-1183","CAN-2002-0862");

 name["english"] = "Flaw in Microsoft VM Could Allow Code Execution (810030)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Hotfix to fix Flaw in Microsoft VM
could Allow Code Execution (810030)

Impact of vulnerability: Three vulnerabilities, the most
serious of which could enable an attacker to gain complete
control over a user's system. 

Maximum Severity Rating: Critical 

Recommendation: Administrators should install the patch immediately. 

Affected Software: 

Versions of the Microsoft virtual machine (Microsoft VM) are
identified by build numbers, which can be determined using the
JVIEW tool as discussed in the FAQ. All builds of the Microsoft
VM up to and including build 5.0.3805 are affected by these
vulnerabilities. 

Supersedes :

http://www.microsoft.com/technet/security/bulletin/ms02-052.asp

See :
http://www.microsoft.com/technet/security/bulletin/ms02-069.asp

Also Note: Requires full registry access (Administrator)
to run the test.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q329077, Flaw in Microsoft VM JDBC";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 SECNAP Network Security, LLC");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_full_access.nasl",
		     "smb_reg_service_pack.nasl",
		     "smb_reg_service_pack_XP.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/WindowsVersion",
		     "SMB/registry_access");
 script_exclude_keys("SMB/samba");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

# will be in Win2k SP4 (i think)
# on win2k, its put into the presp4 directory

version = get_kb_item("SMB/WindowsVersion");
if(!version)exit(0);

# Fixed in Win2003 or newer
if(ereg(pattern:"([6-9]\.[0-9])|(5\.[2-9])", string:version))exit(0);


if("5.0" >< version)
{
# fixed in Service Pack 4
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [4-9]"))exit(0);
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q810030";
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);
 exit(0);
}

if("5.1" >< version)
{
 # fixed in XP service Pack 2
 sp = get_kb_item("SMB/XP/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [2-9]"))exit(0);
}
# lets double check:
 access = get_kb_item("SMB/registry_full_access");
 #can't double check, lets just mark it
 if(!access)exit(0);

key = "SOFTWARE\Microsoft\Active Setup\Installed Components\{08B0E5C0-4FCB-11CF-AAA5-00401C608500}";
item = "Version";

# should be "5,00,3807,0";
 value = registry_get_sz(key:key, item:item);
if(!("3809" >< value))
{
   security_hole(port);
}

