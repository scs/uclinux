#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#
# 
# Ref: http://archives.neohapsis.com/archives/bugtraq/2003-05/0117.html


if(description)
{
 script_id(11631);

 
 script_version("$Revision: 1.2 $");

 name["english"] = "Drag And Zip Overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Drag And Zip - a file compression utility.

There is a flaw in this program which may allow a remote attacker to
execute arbitrary code on this host.

To exploit this flaw, an attacker would need to craft a special
Zip file and send it to a user on this host. Then, the user would
need to open it using Drag And Zip.

Solution : None
Risk Factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of Drag And Zip";

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



rootfile = registry_get_sz(key:"SOFTWARE\Canyon\InstalledApps\DragAndZip", item:"Install Directory");
if(!rootfile)
{
 exit(0);
}
else
{
 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
 exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Dz32.exe", string:rootfile);
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

fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:exe);
if(fid != 0)
{
 security_warning(port);
}
