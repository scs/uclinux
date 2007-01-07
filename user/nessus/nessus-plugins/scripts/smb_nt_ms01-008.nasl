#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10693);
 script_version ("$Revision: 1.13 $");
 script_bugtraq_id(2348);
 script_cve_id("CVE-2001-0016");
 
 name["english"] =  "NTLMSSP Privilege Escalation";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The hotfix for the 'NTLMSSP Privilege Escalation'
problem has not been applied.

This vulnerability allows a malicious user, who has the
right to log on this host locally, to gain additional privileges.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms01-008.asp
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the hotfix Q280119 is installed";
 summary["francais"] = "Détermine si le hotfix Q280119 est installé";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl",
		     "smb_reg_service_pack.nasl"
		     );
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
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
if(version == "4.0") ## &&(sp< 7?)
{
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q299444";
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(value)exit(0);
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q280119";
 value = registry_get_sz(key:key, item:item);
 if(!value)security_hole(port);
}

