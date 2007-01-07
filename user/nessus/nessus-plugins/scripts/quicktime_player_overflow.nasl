#
# This script was written by Renaud Deraison 
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(11506);
 script_version("$Revision: 1.2 $");
 script_cve_id("CAN-2003-0168");
 script_bugtraq_id(7247);
 
 
 name["english"] = "Quicktime player buffer overflow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of the Quicktime player is vulnerable to
a buffer overflow.

To exploit it, an attacker would need a user of this host to
visit a rogue webpage with a malformed link in it. He could
then be able to execute arbitrary code with the rights of the user
visiting the page.
	

Solution : Upgrade to Quicktime Player 6.1
Risk factor : Serious";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of Quicktime Player";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_full_access.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_full_access","SMB/WindowsVersion");


 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;


key = "SOFTWARE\Apple Computer, Inc.\Quicktime";
item = "Version";
version = registry_get_dword(key:key, item:item);
if(!version)exit(0);

if(version < 0x06100000)security_hole(port);
