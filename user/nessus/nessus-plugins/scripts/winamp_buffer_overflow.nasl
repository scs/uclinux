#
# This script was written by Renaud Deraison <rderaison@tenablesecurity.com>
#
# See the Nessus Scripts License for details
#
# Ref:
#  Date: Sat, 4 Jan 2003 05:00:47 -0800
#  From: D4rkGr3y <grey_1999@mail.ru>
#  To: bugtraq@securityfocus.com, submissions@packetstormsecurity.com,
#        vulnwatch@vulnwatch.org
#  Subject: [VulnWatch] WinAmp v.3.0: buffer overflow


if(description)
{
 script_id(11530);
 script_bugtraq_id(6515);
 script_version("$Revision: 1.2 $");

 name["english"] = "WinAMP3 buffer overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using WinAMP3, a popular media player
which handles many files format (mp3, wavs and more...)

This version has a buffer overflow which may allow an attacker
to execute arbitrary code on this host, with the rights of the user
running WinAMP.

To perform an attack, the attack would have to send a malformed
playlist (.b4s) to the user of this host who would then have to
load it by double clicking on it.

Since .b4s are XML-based files, most antivirus programs will let
them in.

Solution : Uninstall this software or upgrade to a version newer than 3.0 build 488
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of WinAMP";

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



rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
if(!rootfile)
{
 exit(0);
}
else
{
 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
 winamp3 =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\WinAmp3\studio.exe", string:rootfile);
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


fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:winamp3);
if(fid)
{
fsize = smb_get_file_size(socket:soc, uid:uid, tid:tid, fid:fid);


off = 0;
data = ReadAndX(socket:soc, uid:uid, tid:tid, fid:fid, count:16384, off:off);
data = str_replace(find:raw_string(0), replace:"", string:data);
version = strstr(data, "ProductVersion");
if(!version)exit(0);

v = "";

for(i=strlen("ProductVersion");i<strlen(version);i++)
{
 if((ord(version[i]) < ord("0") ||
    ord(version[i]) > ord("9")) && 
    version[i] != "." &&
    version[i] != "," &&
    version[i] != " ")break;
 else 
   if(version[i] != " ")v += version[i];
}


if(strlen(v))
{
 if(ereg(pattern:"1,0,0,.*", string:v))
 {
  build = ereg_replace(pattern:"1,0,0,(.*)", replace:"\1", string:v);
  if(int(build) <= 488)security_hole(port);
 }
 }
}

