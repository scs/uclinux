#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(11148);
 script_version("$Revision: 1.4 $");
 script_cve_id("CAN-2002-0370", "CAN-2002-1139"); 

 name["english"] = "Unchecked Buffer in Decompression Functions(Q329048)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Two vulnerabilities exist in the Compressed Folders function: 

An unchecked buffer exists in the programs that handles
the decompressing of files from a zipped file. A
security vulnerability results because attempts to open
a file with a specially malformed filename contained in
a zipped file could possibly result in Windows Explorer
failing, or in code of the attacker's choice being run.

The decompression function could place a file in a
directory that was not the same as, or a child of, the
target directory specified by the user as where the
decompressed zip files should be placed. This could
allow an attacker to put a file in a known location on
the users system, such as placing a program in a
startup directory

Impact of vulnerability: Two vulnerabilities, the most serious
of which could run code of attacker's choice

Maximum Severity Rating: Moderate 

Recommendation: Consider applying the patch to affected systems 

Affected Software: 

Microsoft Windows 98 with Plus! Pack 
Microsoft Windows Me 
Microsoft Windows XP 

See
http://www.microsoft.com/technet/security/bulletin/ms02-054.asp

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q329048, Unchecked Buffer in Decompression functions";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 SECNAP Network Security, LLC");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl",
		     "smb_reg_service_pack_XP.nasl",
		     "smb_reg_service_pack.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/WindowsVersion",
		     "SMB/registry_access");
 script_exclude_keys("SMB/Win2K/ServicePack","SMB/WinNT4/ServicePack");

 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;


access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");

if("5.1" >< version)
{
# fixed in Service Pack 2
 sp = get_kb_item("SMB/XP/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [2-9]"))exit(0);
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Hotfix\Q329048";
# note : despite the microsoft web site, win2k DOES update this reg,
# and it is safer to check, only needs user privs
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);
}
