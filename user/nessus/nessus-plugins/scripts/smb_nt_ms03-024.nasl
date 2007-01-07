#
# This script was written by Renaud Deraison 
#
# See the Nessus Scripts License for details
#
#
#
#

if(description)
{
 script_id(11787);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(8152);
 script_cve_id("CAN-2003-0345");
 
 name["english"] = "SMB Request Handler Buffer Overflow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is vulnerable to a flaw in its SMB stack which may allow
an unauthenticated attacker to corrupt the memory of this host. This
may result in execution of arbitrary code on this host, or an attacker
may disable this host remotely.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-024.asp
 

Risk factor : Serious";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q817606";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_full_access.nasl",
		     "smb_reg_service_pack_XP.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_full_access","SMB/WindowsVersion");
 script_exclude_keys("SMB/Win2003/ServicePack");


 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;


access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");




if(ereg(pattern:"(5\.[2-9]|[6-9]\.[0-9])", string:version))exit(0);

#
# Never fixed in 4.0
#
if("4.0" >< version)
{
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q817606";
 item = "Description";
 value = registry_get_sz(key:key, item:item);
 if(!value){
 	security_hole(port);
	}
 exit(0);
}


if("5.0" >< version)
{
# fixed in Service Pack 4
 sp = get_kb_item("SMB/Win2K/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [4-9]"))exit(0);
 key = "SOFTWARE\Microsoft\Windows 2000\SP4\Q817606";
}

if("5.1" >< version)
{
 # fixed in XP service Pack 2
 sp = get_kb_item("SMB/XP/ServicePack");
 if(ereg(string:sp, pattern:"Service Pack [2-9]"))exit(0);
 key = "SOFTWARE\Microsoft\Windows XP\SP2\Q817606";
}

value = registry_get_sz(key:key, item:item);
if(!value)security_hole(port);
 
