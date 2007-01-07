#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11777);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "SMB share hosting copyrighted material";
 script_name(english:name["english"]);
 
 desc["english"] = "
This script connects to the remotely accessible SMB shares
and attempts to find potentially copyrighted contents on it 
(such as .mp3, .ogg, .mpg or .avi files).";

 

 script_description(english:desc["english"]);
 
 summary["english"] = "Finds .mp3, .avi and .wav files";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Peer-To-Peer File Sharing";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_enum_shares.nasl",
		     "smb_login_as_users.nasl",
		     "smb_accessible_shares.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = kb_smb_transport();
if(!port) port = 139;

function get_dirs(socket, uid, tid, basedir, level)
{
 local_var ret,ret2, r, subdirs, subsub;
 

 if(level > 3)
 	return NULL;
	
 subdirs = NULL;
 ret = FindFirst2(socket:soc, uid:uid, tid:tid, pattern:basedir + "\*");
 if(isnull(ret))
 	return NULL;
	
 foreach r (ret)
 { 
  if(isnull(ret2))
  	ret2 = make_list(basedir + "\" + r);
  else
  	ret2 = make_list(ret2, basedir + "\" + r);
	
  if("." >!< r)
  	subsub  = get_dirs(socket:soc, uid:uid, tid:tid, basedir:basedir + "\" + r, level:level + 1);
  if(!isnull(subsub))
  {
  	if(isnull(subdirs))subdirs = make_list(subsub);
  	else	subdirs = make_list(subdirs, subsub);
  }
 }
 
 if(isnull(subdirs))
 	return ret2;
 else
 	return make_list(ret2, subdirs);
}

		

function list_supicious_files(share)
{
 num_suspects = 0;
 soc = open_sock_tcp(port);
 if(soc)
 {
 r = smb_session_request(soc:soc,  remote:name);
 if(!r)return(FALSE);

  #
  # Negociate the protocol
  #
  prot = smb_neg_prot(soc:soc);
  if(!prot)exit(0);
  #
  # Set up our null session 
  #
  r = smb_session_setup(soc:soc, login:login, password:pass, domain:dom, prot:prot);
  if(!r)return(FALSE);
  # and extract our uid
  uid = session_extract_uid(reply:r);

  suspect = NULL;
  r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
  if(r)
  { 
   tid = tconx_extract_tid(reply:r);
   dirs = get_dirs(socket:soc, uid:uid, tid:tid, basedir:NULL, level:0);
  
   foreach dir (dirs)
   {
    if(ereg(pattern:".*\.(mp3|mpg|mpeg|ogg|avi)$", string:dir, icase:TRUE))
    {
     if(isnull(suspect)) suspect = make_list(dir);
     else suspect = make_list(suspect, dir);
     num_suspects ++;
     if (num_suspects >= 40 )
     {
      suspect = make_list(suspect, "... (more) ...");
      return suspect;
     }
    }
   }
  }
  else close(soc);
  }
  return(suspect);
}		


#
# Here we go
#		


name = kb_smb_name();
if(!name)exit(0);




login = kb_smb_login();
pass =  kb_smb_password();

if(!login)login = "";
if(!pass)pass = "";

dom = kb_smb_domain();


if(!get_port_state(port))exit(0);
shares = get_kb_list("SMB/shares");
if(isnull(shares))exit(0);
else shares = make_list(shares);


report = NULL;
foreach share (shares) 
{
  files = list_supicious_files(share:share);
  if(!isnull(files))
  {
   report += " + " + share + ' :\n\n';
   foreach f (files)
   {
    report += '  - ' + f + '\n';
   }
   report += '\n\n';
  }
}

if(report != NULL)
 {
  report = "
Here is a list of files which have been found on the remote SMB shares.
Some of these files may contain copyrighted materials, such as commercial
movies or music files. 

If any of this file actually contains copyrighted material and if
they are freely swapped around, your organization might be held liable
for copyright infrigement by associations such as the RIAA or the MPAA.

" + report + "

Solution : Delete all the copyrighted files";

  security_warning(port:port, data:report);
 }
