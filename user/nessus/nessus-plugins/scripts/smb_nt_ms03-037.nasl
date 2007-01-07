#
# (C) Tenable Network Security
#
# Ref: http://www.microsoft.com/technet/security/bulletin/ms03-037.asp

if(description)
{
 script_id(11832);
 script_bugtraq_id(8534);
 script_cve_id("CAN-2003-0347");
 
 
 script_version("$Revision: 1.3 $");

 name["english"] = "Visual Basic for Application Overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Microsoft Visual Basic for Applications
which is vulnerable to a buffer overflow when handling malformed documents.

An attacker may exploit this flaw to execute arbitrary code on this host, by
sending a malformed file to a user of the remote host.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms03-037.asp
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of vbe.dll and vbe6.dll";

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



rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
if(!rootfile)
{
 exit(0);
}
else
{
 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
 vbe6 =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft Shared\VBA\VBA6\vbe6.dll", string:rootfile);
 vbe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft Shared\VBA\vbe.dll", string:rootfile);
}




function get_ver(filename)
{
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

fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:filename);
if(!fid)return NULL;
else
{
fsize = smb_get_file_size(socket:soc, uid:uid, tid:tid, fid:fid);
if(fsize > 300000)max = 300000;
else max = fsize;
for(i=16384;i<max;i+=16384)
{
off = fsize - i;
data = ReadAndX(socket:soc, uid:uid, tid:tid, fid:fid, count:16384, off:off);
data = str_replace(find:raw_string(0), replace:"", string:data);

version = strstr(data, "ProductVersion");
if(version)break;
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
 }
 return v;
}



a = get_ver(filename:vbe);
if(a)
{
 # Fixed in 5.0.78.15
 if(egrep(pattern:"^([0-4]\.|5\.0\.([0-9]\.|[0-6].*|7[0-7]|78\.([0-9]$|1[0-4])))", string:a))
 	{ security_hole(kb_smb_transport()); exit(0); }
}

a = get_ver(filename:vbe6);
if(a)
{
 # Fixed in 6.4.99.69
 if(egrep(pattern:"^([0-5]\.|6\.(0?[0-3]\.|4\.([0-9]\.|[0-8][0-9]\.|9[0-8]\.|99\.([0-9]$|[0-5][0-9]|6[0-8]))))",
 	  string:a))
	  {
	   security_hole(kb_smb_transport()); exit(0);
	  }
}
