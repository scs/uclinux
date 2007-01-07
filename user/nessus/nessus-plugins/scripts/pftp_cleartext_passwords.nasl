#
# (C) Tenable Network Security
#
# ref: http://www.securiteam.com/windowsntfocus/5OP100AA0G.html
#

if(description)
{
 script_id(11693);
 script_version ("$Revision: 1.2 $");
 
 
 name["english"] = "PFTP clear-text passwords";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server is running PFTP.

This software stores the list of user names and passwords 
in clear text in \Program Files\PFTP\PFTPUSERS3.USR.

An attacker with a full access to this host may use this flaw
to gain access to other FTP servers used by the same users.

Solution : None
Risk Factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks PFTPUSERS3.USR";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_require_ports(139, 445);
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/domain","SMB/transport");
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
 db =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\PFTP\PFTPUSERS3.USR", string:rootfile);
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


fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:db);
if(fid)
{
 security_warning(port);
 exit(0);
}


