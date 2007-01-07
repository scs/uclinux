#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#
# Ref: http://www.microsoft.com/technet/security/bulletin/ms02-021.asp

if(description)
{
 script_id(11325);
 script_cve_id("CVE-2002-1056");
 script_bugtraq_id(4397);
 
 script_version("$Revision: 1.9 $");

 name["english"] = "Word can lead to Script execution on mail reply";

 script_name(english:name["english"]);
 
 desc["english"] = "
Outlook 2000 and 2002 provide the option to use Microsoft Word as 
the e-mail editor when creating and editing e-mail in RTF or HTML.

There is a flaw in some versions of Word which may allow an attacker
to execute arbitrary code when the user replies to a specially
formed message using Word.

An attacker may use this flaw to execute arbitrary code on this host.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms02-021.asp
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of WinWord.exe";

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



rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
if(!rootfile)
{
 exit(0);
}
else
{
 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
 file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft Office\Office\WinWord.exe", string:rootfile);
 file10 = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft Office\Office10\WinWord.exe", string:rootfile);
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
if(!fid) fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file10);
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
 set_kb_item(name:"SMB/Office/Word/Version", value:v);
 if(ereg(pattern:"^9\..*", string:v))
 {
  # Word 2000 - patched in WinWord 9.0.6328
  middle =  ereg_replace(pattern:"9\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  minor =   ereg_replace(pattern:"9\.[0-9]*\.([0-9]*)$", string:v, replace:"\1");
  if(middle == 0 && minor < 6328)security_warning(port);
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # Word 2002 - updated in 10.0.4009.3501
  
  middle =  ereg_replace(pattern:"10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  minor  =  ereg_replace(pattern:"10\.0\.[0-9]*\.([0-9]*)$", string:v, replace:"\1");
  if(middle < 4009)security_warning(port);
  else if(middle == 4009 && minor < 3501)security_warning(port);
 }
}
