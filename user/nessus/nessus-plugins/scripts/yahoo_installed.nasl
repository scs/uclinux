#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11432);
 script_bugtraq_id(2299, 4162, 4163, 4164, 4173, 4837, 4838, 5579, 6121);
 script_cve_id("CAN-2002-0320", "CAN-2002-0321", "CAN-2002-0031", "CVE-2002-0032", "CAN-2002-0322");  
 
 script_version("$Revision: 1.7 $");

 name["english"] = "Yahoo!Messenger is installed";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Yahoo!Messenger - an instant messenging software, 
which may not be suitable for a business environment. 

Solution : Uninstall this software
Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if Yahoo!Messenger is installed";

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


rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Yahoo! Messenger", item:"DisplayName");
if(rootfile)
{
 security_note(kb_smb_transport());
}

