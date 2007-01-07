#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#
# Ref: http://www.microsoft.com/technet/security/bulletin/ms02-013.asp
#
# Supercedes : MS99-031, MS99-045, MS00-011, MS00-059, MS00-075, MS00-081
#

if(description)
{
 script_id(11326);
 script_cve_id("CAN-2002-0058", "CVE-2002-0078");
 script_bugtraq_id(4228, 4392);
 script_version("$Revision: 1.6 $");

 name["english"] = "Cumulative VM update";

 script_name(english:name["english"]);
 
 desc["english"] = "
The Microsoft VM is a virtual machine for the Win32 operating environment.

There are numerous security flaws in the remote Microsoft VM which
could allow an attacker to execute arbitrary code on this host.

To exploit this flaw, an attacker would need to set up a malicious
web site with a rogue Java applet and lure the user of this host
to visit it. The java applet could then execute arbitrary commands
on this host.


Solution : See http://www.microsoft.com/technet/security/bulletin/ms02-013.asp
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of JView.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
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
 # Fixed in 5.0.3805
 
 vers = split(v, sep:".");
 
 
 if(int(vers[0]) > 5)exit(0);
 
 if(int(vers[0]) < 4)security_hole(port);
 else 
 {
  if(int(vers[1]) == 0 && int(vers[2]) < 3805)security_hole(port);
 }
}
