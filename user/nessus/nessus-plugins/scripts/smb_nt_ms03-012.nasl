#
# written by Renaud Deraison <renaud@tenablesecurity.com>
#

if(description)
{
 script_id(11534);
 script_cve_id("CAN-2003-0110");
 script_bugtraq_id(7314);
 script_version ("$Revision: 1.3 $");

 name["english"] = "Microsoft ISA Server Winsock Proxy DoS (MS03-012)";

 script_name(english:name["english"]);
 
 desc["english"] = "
A vulnerability in Microsoft Proxy Server 2.0 and ISA Server 2000 
allows an attacker to cause a denial of service of the remote Winsock
proxy service by sending a specially crafted packet which would cause
100% CPU utilization on the remote host and make it unresponsive.


Solution : see http://www.microsoft.com/technet/security/bulletin/MS03-012.asp
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ISA Server HotFix SP1-257";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
        "smb_login.nasl","smb_registry_access.nasl",
       "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
       "SMB/WindowsVersion",
       "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

# Check ISA installed
key = "SOFTWARE\Microsoft\Fpc";
item = "ClassName";
value = registry_get_sz(key:key, item:item);
if(!value)exit(0);

 
# Check if the patch is installed
key = "SOFTWARE\Microsoft\Fpc\Hotfixes\SP1\257";
item = "Comments";
value = registry_get_sz(key:key, item:item);

if(!value)security_hole(port);
