
#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details

if(description)
{
 script_id(11322);
 script_cve_id("CAN-2002-0643");
 script_version("$Revision: 1.6 $");

 name["english"] = "MS SQL Installation may leave passwords on system";

 script_name(english:name["english"]);
 
 desc["english"] = "
The installation process of the remote MS SQL server left 
files named 'setup.iss' on the remote host.

These files contain the password assigned to the 'sa' account
of the remote database.

An attacker may use this flaw to gain full administrative
access to your database.

See
http://www.microsoft.com/technet/security/bulletin/ms02-035.asp

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Reads %windir%\setup.iss";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_nt.inc");





rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"SystemRoot");
if(!rootfile)
{
 rootfile = "\WinNT\setup.iss";
 share = "C$";
}
else
{
 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
 rootfile =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\setup.iss", string:rootfile);
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

foreach file (make_list("\MSSQL7\Install\setup.iss", rootfile))
{
fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
 if(fid)
 {
 resp = ReadAndX(socket:soc, uid:uid, fid:fid, tid:tid, count:16384, off:0);
 if("svPassword=" >< resp){
	security_hole(port);
	exit(0);
	}
 }
}
