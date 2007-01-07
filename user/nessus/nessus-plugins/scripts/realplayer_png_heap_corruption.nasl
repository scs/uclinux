#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11496);
 script_bugtraq_id(7177);
 script_cve_id("CAN-2003-0141");  
 
 script_version("$Revision: 1.2 $");

 name["english"] = "RealPlayer PNG deflate heap corruption";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has RealPlayer installed. There is a flaw
in the remote version which may allow an attacker to execute
arbitrary code on the remote host, with the privileges of the
user running RealPlayer.

To do so, an attacker would need to send a corrupted PNG file to
a remote user and have him open it using RealPlayer.

Solution : Go to http://service.real.com/help/faq/security/securityupdate_march2003.html

If you have uninstalled RealPlayer you may wish to delete
the old registry key at SOFTWARE\RealNetworks\RealPlayer.

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of RealPlayer";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
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


version = registry_get_sz(key:"SOFTWARE\RealNetworks\RealPlayer", item:"version");
 
 
if(version)
{
 if(ereg(pattern:"6\.0\.9\.([0-9]|[0-9][0-9]|[0-4][0-9][0-9]|5[0-7][0-9]|58[0-4])$", string:version))
 		security_hole(port);
		
 if(ereg(pattern:"6\.0\.10\..*", string:version))
 		security_hole(port);
		
 if(ereg(pattern:"6\.0\.11\.([0-9]|[0-9][0-9]|[0-7][0-9][0-9]|8[0-4][0-9]|85[0-3])$", string:version))
 		security_hole(port);		
}

