#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#
# Ref:
#  From: "Andreas Constantinides" <megahz@megahz.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: Plaintext Password in Settings.ini of CesarFTP
#  Date: Tue, 20 May 2003 10:25:56 +0300


if(description)
{
 script_id(11640);
 script_cve_id("CAN-2003-0329");

 
 script_version("$Revision: 1.4 $");

 name["english"] = "CesarFTP stores passwords in cleartext";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has the program CesarFTP.exe installed.

There is a design issue in the program which makes it store
the username and password of the FTP server in cleartext in
the file 'settings.ini'.

Any user with an account on this host may read this file and
use the password to connect to this FTP server.

Solution : None
Risk : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of CesarFTP's settings.ini";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
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



rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
if(!rootfile)
{
 exit(0);
}
else
{
 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
 exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\CesarFTP\Settings.ini", string:rootfile);
 }





name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();
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

fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:exe);
if(fid != 0)
{
 data = ReadAndX(socket:soc, uid:uid, tid:tid, fid:fid, count:16384, off:0);
 if('Password= "' >< data && 'Login= "' >< data) security_warning(port);
}
