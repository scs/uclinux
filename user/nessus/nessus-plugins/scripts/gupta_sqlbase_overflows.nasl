#
#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11363);
 script_bugtraq_id(6808);

 script_version("$Revision: 1.4 $");

 name["english"] = "Gupta SQLBase EXECUTE buffer overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the Gupta SQLBase server
which is older than or equal to 8.1.0.

There is a flaw in this version which allows an attacker
to execute arbitrary code on this host, provided that
he can make SQL statements to it (usually thru a named pipe),
and therefore escalate privileges (and gain LocalSystem privileges).

Solution : Upgrade to version newer than 8.1.0
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of the remote Gupta SQLBase server";

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



rootfile = registry_get_sz(key:"SYSTEM\CurrentControlSet\Services\Gupta SQLBase", item:"ImagePath");
if(!rootfile)
{
 exit(0);
}
else
{
 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
 file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:rootfile);
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
if(!fid)fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);

fsize = smb_get_file_size(socket:soc, uid:uid, tid:tid, fid:fid);

off = fsize - 16384;
data = ReadAndX(socket:soc, uid:uid, tid:tid, fid:fid, count:16384, off:off);
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
 if(ereg(pattern:"^(([^0-9]?[0-7]\.[0-9]\.[0-9])|(8\.(0\.[0-9]|1\.0)))[^0-9]*$", string:v))
  security_hole(port);
}
