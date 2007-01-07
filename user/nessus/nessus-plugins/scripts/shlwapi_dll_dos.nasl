#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details

if(description)
{
 script_id(11583);
 script_bugtraq_id(7402);
 script_version("$Revision: 1.2 $");

 name["english"] = "Microsoft Shlwapi.dll Malformed HTML form tag DoS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the shlwapi.dll which crashes
when processing a malformed HTML form.

An attacker may use this flaw to prevent the users of this host from
working properly.

To exploit this flaw, an attacker would need to send a malformed
HTML file to the remote user, either by e-mail or by making him
visit a rogue web site.

Solution : None
Risk Factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of shlwapi.dll";

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
 script_exclude_keys("SMB/samba");
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
 file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\System32\shlwapi.dll", string:rootfile);
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

fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
if(!fid)exit(0);

fsize = smb_get_file_size(socket:soc, uid:uid, tid:tid, fid:fid);



off = fsize - 65535;

for(i=0;i<4;i=i+1)
{
 data += ReadAndX(socket:soc, uid:uid, tid:tid, count:16384, off:off);
 off += 16383;
}

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
 security_warning(port);
 exit(0);
 
 # 
 # It's not fixed yet....
 # 
 vers = split(v, sep:".");
 
 
 if(int(vers[0]) > 5)exit(0);
 
 if(int(vers[0]) < 4){ security_hole(port); exit(0); }
 else 
 {
  if(int(vers[1]) > 6)exit(0);
  else if(int(vers[2]) > 0)exit(0);
  else if(int(vers[3]) >= 8513)exit(0);
  else security_hole(port);
 }
}
