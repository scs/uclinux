#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(11146);
 script_version("$Revision: 1.5 $");
 script_cve_id("CAN-2002-0863"); # and 864
 script_bugtraq_id(5410);

 name["english"] = "Microsoft RDP flaws could allow sniffing and DOS(Q324380)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Remote Data Protocol (RDP) version 5.0 in Microsoft
Windows 2000 and RDP 5.1 in Windows XP does not
encrypt the checksums of plaintext session data,
which could allow a remote attacker to determine the
contents of encrypted sessions via sniffing, and 
Remote Data Protocol (RDP) version 5.1 in Windows
XP allows remote attackers to cause a denial of
service (crash) when Remote Desktop is enabled via a
PDU Confirm Active data packet that does not set the
Pattern BLT command.

Impact of vulnerability: Two vulnerabilities:
information disclosure, denial of service.

Maximum Severity Rating: Moderate. 

Recommendation: Administrators of Windows
2000 terminal servers and Windows XP users
who have enabled Remote Desktop should apply
the patch.

Affected Software: 

Microsoft Windows 2000 
Microsoft Windows XP

See
http://www.microsoft.com/technet/security/bulletin/ms02-051.asp

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q324380, Flaws in Microsoft RDP";

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
 script_exclude_keys("SMB/XP/ServicePack","SMB/WinNT4/ServicePack");

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
# win2k servers only.  Not workstations
 key = "SYSTEM\CurrentControlSet\Control\ProductOptions";
 item = "ProductType";
 value = registry_get_sz(key:key, item:item);
 if(value == "WinNT")exit(0);


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


if("4.0" >< version)exit(0); # not for NT 4.0
if(ereg(pattern:"([6-9]\.[0-9])|(5\.[2-9])", string:version))exit(0);

 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Hotfix\Q324380";
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);

