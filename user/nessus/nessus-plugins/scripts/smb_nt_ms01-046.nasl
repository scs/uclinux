#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10734);
 script_version ("$Revision: 1.18 $");
 script_bugtraq_id(3215);
 script_cve_id("CVE-2001-0659");
 
 name["english"] =  "IrDA access violation patch";
 
 script_name(english:name["english"]);
 	     
 
 desc["english"] = "
The hotfix for the 'IrDA access violation patch'
problem has not been applied.

This vulnerability can allow an attacker who is physically
near the W2K host to shut it down using a remote control.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms01-046.asp
Or POST SP2 Security Rollup:
http://www.microsoft.com/windows2000/downloads/critical/q311401/default.asp

Risk factor : Serious";




 script_description(english:desc["english"]);
 		    
 
 summary["english"] = "Determines whether the hotfix  Q252795 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access",
 		     "SMB/WindowsVersion");
 script_exclude_keys("SMB/XP/ServicePack","SMB/WinNT4/ServicePack");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;


#---------------------------------------------------------------------#
# Here is our main()                                                  #
#---------------------------------------------------------------------#

version = get_kb_item("SMB/WindowsVersion");
if(version == "5.0")
{
 # check for Win2k post SP2 SRP first.
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\SP2SRP1";
 item = "Comments";
 value = string(registry_get_sz(key:key, item:item));
 if(value)exit(0);
 # then for service pack 3.
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [3-9]"))exit(0);

 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q252795";
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(!value)
 {
 security_hole(port);
 exit(0);
 }
}
