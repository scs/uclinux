#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11426);
 script_bugtraq_id(3135, 4121, 4122, 5317, 6435, 6747);
 script_cve_id("CAN-2002-0314", "CAN-2002-0315");  
 
 script_version("$Revision: 1.3 $");

 name["english"] = "Kazaa is installed";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Kazaa - a p2p software, which may not 
be suitable for a business environment. 

Solution : Uninstall this software
Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if Kazaa is installed";

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


rootfile = registry_get_sz(key:"SOFTWARE\Kazaa\CloudLoad",
 item:"ExeDir");
if(rootfile)
{
 security_note(get_kb_item("SMB/transport"));
}

