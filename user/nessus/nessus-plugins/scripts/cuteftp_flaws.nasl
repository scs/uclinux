#
# (C) Tenable Network Security
#


if(description)
{
 script_id(11756);
 script_bugtraq_id(6786, 6642);
 
 script_version("$Revision: 1.2 $");

 name["english"] = "CuteFTP multiple flaws";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has the program CuteFTP.exe installed.

CuteFTP is a FTP client which contains two overflow conditions
which may be exploited by an attacker to gain a shell on this
host.

To exploit these vulnerabilities, an attacker would need to set
up a rogue FTP server and lure a user of this host to browse it
using CuteFTP.

Solution : Upgrade to CuteFTP 5.0.2.0 or newer
Risk Factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of CuteFTP.exe";

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



rootfile = registry_get_sz(key:"SOFTWARE\GlobalScape Inc.\CuteFTP", item:"CmdLine");
if(!rootfile)
{
 exit(0);
}
else
{
 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
 exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:rootfile);
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
 fsize = smb_get_file_size(socket:soc, uid:uid, tid:tid, fid:fid);
 off = fsize - 176128;
 data = ReadAndX(socket:soc, uid:uid, tid:tid, fid:fid, count:16384, off:off);
 data = str_replace(find:raw_string(0), replace:"", string:data);
 version = strstr(data, "ProductVersion");
 
 if(!version)exit(0);
 
 for(i=strlen("ProductVersion");i<strlen(version);i++)
 {
 if((ord(version[i]) < ord("0") ||
    ord(version[i]) > ord("9")) && 
    version[i] != ".")break;
 else 
   v += version[i];
} 

 if(ereg(pattern:"^([0-4]\.|5\.0\.[01]\.)", string:v))
 {
  security_hole(port);
 }
}
