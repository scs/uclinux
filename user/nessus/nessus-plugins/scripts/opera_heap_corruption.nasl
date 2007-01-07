#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11578);
 script_bugtraq_id(7450);
 script_version("$Revision: 1.2 $");

 name["english"] = "Opera remote heap corruption vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Opera - an alternative web browser.

The version installed has a buffer overflow condition in the code
which handles the file extensions of the remote web pages.

To exploit them, an attacker would need to set up a rogue web site, then
lure a user of this host visit it using Opera. He would then be able
to execute arbitrary code on this host.

Solution : None at this time
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Opera.exe";

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



rootfile = registry_get_sz(key:"SOFTWARE\Netscape\Netscape Navigator\5.0, Opera\Main", item:"Install Directory");
if(!rootfile)
{
 exit(0);
}
else
{
 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
 file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Opera.exe", string:rootfile);
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



off = fsize - 90000;

while(fsize != off)
{
data = ReadAndX(socket:soc, uid:uid, tid:tid, count:16384, off:off);
data = str_replace(find:raw_string(0), replace:"", string:data);
version = strstr(data, "ProductVersion");
if(!version)off += 16383;
else break;
}

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
  report = "
We have determined that you are running Opera v." + v + ". This version
has a buffer overflow condition in the code which handles the file extensions 
of the remote web pages which may allow an attacker to execute arbitrary
code on this host.

To exploit these flaws, an attacker would need to set up a rogue website
and lure a user of this host visit it using Opera. He would then be able
to execute arbitrary code on this host.

Solution : Upgrade to version 7.03 or newer
Risk Factor : High";

 # minor =  ereg_replace(pattern:"[0-9]\.([0-9]*)$", string:v, replace:"\1");
 #  major =  ereg_replace(pattern:"([0-9])\.[0-9]*$", string:v, replace:"\1");
 # if(int(major) < 7 || (int(major) == 7 && int(minor) < 3))security_hole(port:port, data:report);
 security_hole(port:port, data:report);
}
