#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11429);
 script_bugtraq_id(668, 4028, 4316, 4675, 4827);
 script_cve_id("CAN-1999-1484", "CAN-2002-0228", "CAN-2002-0472");  
 
 script_version("$Revision: 1.2 $");

 name["english"] = "Windows Messenger is installed";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Windows Messenger - an instant messenging software, 
which may not be suitable for a business environment. 

Solution : Uninstall this software
Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if Windows Messenger is installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Xue Yong Zhi");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/domain","SMB/transport");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_nt.inc");


rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\MessengerService", item:"InstallationDirectory");
if(rootfile)
{
 security_note(port:get_kb_item("SMB/transport"));
}

