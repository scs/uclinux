#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#
# 

if(description)
{
 script_id(11625);
 script_bugtraq_id(7022);
 
 script_version("$Revision: 1.2 $");

 name["english"] = "DrWeb Folder Name Overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running DrWeb - an antivirus.

There is a flaw in the remote version of Dr.Web which may make it crash 
when scanning files whose name is excessively long.

An attacker may use this flaw to execute arbitrary code on this host.
To exploit it, an attacker would need to send a file to the remote host
and have it scanned by this software.

Solution : Upgrade to version 4.29b or newer
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of Dr.Web";

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



rootfile = registry_get_sz(key:"SOFTWARE\DialogueScience\DrWeb", item:"Path");
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

 off = fsize - 16384;
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
 if("4.29" >< v)
 	v = v + version[i];
	
 if(ereg(pattern:"([123]\..*|4\.([0-9][^0-9]|1[0-9]|2[0-8]|29a?))", string:v))
 	security_warning(port);
}
