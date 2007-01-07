#
# This script was written by Michael Scheidell <scheidell@fdma.com>
# based on template from Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10806);
 script_version ("$Revision: 1.10 $");
 script_bugtraq_id(3313);
 script_cve_id("CVE-2001-0662");
 
 name["english"] =  "RPC Endpoint Mapper can Cause RPC Service to Fail";
 
 script_name(english:name["english"]);
 	     
 
 desc["english"] = "
The hotfix for the 'RPC Endpoint Mapper Service on NT 4 has not been applied'
problem has not been applied.

Because the endpoint mapper runs within the RPC service itself, exploiting this
vulnerability would cause the RPC service itself to fail, with the attendant loss
of any RPC-based services the server offers, as well as potential loss of some COM
functions. Normal service could be
 restored by rebooting the server. 

Solution : See http://www.microsoft.com/technet/security/bulletin/ms01-048.asp
Risk factor : Serious";


 script_description(english:desc["english"]);
 		    
 
 summary["english"] = "Determines whether the hotfix Q305399 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl",
		     "smb_reg_service_pack.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access",
                      "SMB/WindowsVersion");
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

if(version == "4.0")
{
 key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Hotfix\Q305399";
 item = "Comments";
 value = registry_get_sz(key:key, item:item);
 if(!value)
 {
 security_hole(port);
 exit(0);
 }
}
