
#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details

if(description)
{
 script_id(11330);
 script_bugtraq_id(1281);
 script_cve_id("CVE-2000-0402");
 script_version("$Revision: 1.3 $");

 name["english"] = "MS SQL7.0 Service Pack may leave passwords on system";

 script_name(english:name["english"]);
 
 desc["english"] = "
The installation process of the remote MS SQL server left 
files named 'sqlsp.log' on the remote host.

These files contain the password assigned to the 'sa' account
of the remote database.

An attacker may use this flaw to gain full administrative
access to your database.

See
http://www.microsoft.com/technet/security/bulletin/ms00-035.asp

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Reads %temp%\sqlsp.log";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/WindowsVersion",
		     "SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_nt.inc");





rootfile = registry_get_sz(key:"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", item:"TEMP");
if(!rootfile)
{
 rootfile = "\WinNT\TEMP\sqlsqp.log";
 share = "C$";
}
else
{
 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
 rootfile =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\sqlsp.log", string:rootfile);
}


name 	= kb_smb_name();
login	= kb_smb_login();
pass  	= kb_smb_password();
domain 	= kb_smb_domain();
port    = kb_smb_transport();
if(!port) port = 139;



if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);


r = smb_session_request(soc:soc, remote:name);
if(!r)exit(0);

prot = smb_neg_prot(soc:soc);
if(!prot)exit(0);

r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain, prot:prot);
if(!r)exit(0);

uid = session_extract_uid(reply:r);

r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
tid = tconx_extract_tid(reply:r);
if(!tid)exit(0);

fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:rootfile);
if(fid)security_warning(port);
