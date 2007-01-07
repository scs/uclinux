#
# written by Renaud Deraison <deraison@cvs.nessus.org>
#


if(description)
{
 script_id(11528);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CAN-2003-0111");
 
 name["english"] = "Flaw in Microsoft VM (816093)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a Microsoft VM machine which has a bug
in its bytecode verifier which may allow a remote attacker to execute
arbitrary code on this host, with the privileges of the user running the VM.

To exploit this vulnerability, an attacker would need to send a malformed
applet to a user on this host, and have him execute it. The malicious
applet would then be able to execute code outside the sandbox of the VM.


Solution : See http://www.microsoft.com/technet/security/bulletin/ms03-011.asp
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of the remote VM";

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



rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"SystemRoot");
if(!rootfile)
{
 exit(0);
}
else
{
 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
 file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\System32\Jview.exe", string:rootfile);
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

fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
if(!fid)exit(0);

fsize = smb_get_file_size(socket:soc, uid:uid, tid:tid, fid:fid);



off = fsize - 16384;
data = ReadAndX(socket:soc, uid:uid, tid:tid, count:16384, off:off);
data = str_replace(find:raw_string(0), replace:"", string:data);

version = strstr(data, "ProductVersion");
if(!version)exit(0);

v = "";

for(i=strlen("ProductVersion");i<strlen(version);i++)
{
 if((ord(version[i]) < ord("0") ||
    ord(version[i]) > ord("9")) && 
    version[i] != ".")break;
 else 
   v += version[i];
}


if(strlen(v))
{
 # Fixed in >5.0.3809
 
 vers = split(v, sep:".");
 
 
 if(int(vers[0]) > 5)exit(0);
 
 if(int(vers[0]) < 4)security_hole(port);
 else 
 {
  if(int(vers[1]) == 0 && int(vers[2]) <= 3809)security_hole(port);
 }
}
