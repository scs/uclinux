#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11425);

#TODO: too long bugtraq id
# script_bugtraq_id(246, 132, 929, 1463, 1307, 2664, 3813, 4514, 5239, 5247, 3226, 5295);
 script_cve_id("CAN-1999-1418", "CAN-1999-1440", "CAN-2000-0046", "CAN-2000-0564", "CVE-2000-0552", "CAN-2001-0367", "CVE-2002-0028", "CAN-2001-1305");
 
 script_version("$Revision: 1.4 $");

 name["english"] = "ICQ is installed";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using ICQ - a p2p software, 
which may not be suitable for a business environment. 

Solution : Uninstall this software
Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if ICQ is installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Xue Yong Zhi");
 family["english"] = "Peer-To-Peer File Sharing";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/domain","SMB/transport");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_nt.inc");


rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\CurrentVersion\Windows\Uninstall\ICQ", item:"DisplayName");
if(rootfile)
{
 security_note(get_kb_item("SMB/transport"));
 exit(0); 
}

rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\CurrentVersion\Windows\Uninstall\ICQLite", item:"DisplayName");
if(rootfile)
{
 security_note(get_kb_item("SMB/transport"));
 exit(0); 
}


