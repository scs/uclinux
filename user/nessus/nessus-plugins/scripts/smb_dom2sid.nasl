#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10398);
 script_version ("$Revision: 1.29 $");
 script_bugtraq_id(959);
 script_cve_id("CVE-2000-1200");
 
 name["english"] = "SMB get domain SID";
 name["francais"] = "Obtentention du SID du domaine par SMB";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "

This script emulates the call to LsaQueryInformationPolicy()
to obtain the domain (or host) SID (Security Identifier).

The domain/host SID can then be used to get the list
of users of the domain or the list of local users

Risk factor : Low";

 desc["francais"] = "

Ce script émule la fonction LsaQueryInformationPolicy()
afin d'obtenir le SID du domaine ou de la
machine


Le SID peut ensuite etre utilisé pour récuperer la
liste des utilisateurs du domaine ou les utilisateurs
locaux. 

Facteur de risque : faible";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Gets the domain SID";
 summary["francais"] = "Obtention du SID du domaine";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_scope.nasl",
 		     "netbios_name_get.nasl",
 		     "smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/test_domain");
 script_require_ports(139, 445);
 exit(0);
}


d = get_kb_item("SMB/test_domain");
if(!d)exit(0);

include("smb_nt.inc");

port = kb_smb_transport();
if(!port)port = 139;




#--------------------------------------------------------#
# Request the creation of a pipe to lsarpc. We will      #
# then use it to do our work                             #
#--------------------------------------------------------#
function smbntcreatex_lsarpc(soc, uid, tid)
{
 tid_high = tid / 256;
 tid_low  = tid % 256;
 
 uid_high = uid / 256;
 uid_low  = uid % 256;
 
  req = raw_string(0x00, 0x00,
  		   0x00, 0x5B, 0xFF, 0x53, 0x4D, 0x42, 0xA2, 0x00,
		   0x00, 0x00, 0x00, 0x18, 0x03, 0x00, 0x50, 0x81,
		   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		   0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		   0x00, 0x00, 0x18, 0xFF, 0x00, 0x00, 0x00, 0x00,
		   0x07, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
		   0x00, 0x00, 0x9F, 0x01, 0x02, 0x00, 0x00, 0x00,
		   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		   0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00,
		   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
		   0x00, 0x00, 0x00, 0x08, 0x00, 0x5C, 0x6C, 0x73,
		   0x61, 0x72, 0x70, 0x63, 0x00);

 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4000);
 if(!r)return(FALSE);
 if(ord(r[9])==0x00)return(r);
 else return(FALSE);
}



#---------------------------------------------------------#
# Set up the pipe request by calling LSA_OPENPOLICY       #
#---------------------------------------------------------#
		
function pipe_request_lsa_open_policy_setup(soc, uid, tid, pipe)
{
 tid_low = tid % 256;
 tid_high = tid / 256;
 uid_low = uid % 256;
 uid_high = uid / 256;
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 
 req = raw_string(0x00, 0x00,
 		  0x00, 0x94, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x00, 0x50, 0x81,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x06, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  0x80, 0x00, 0x10, 0x00, 0x00, 0x48, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4C,
		  0x00, 0x48, 0x00, 0x4C, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, 0x51, 0x00, 0x5C, 0x50, 0x49,
		  0x50, 0x45, 0x5C, 0x00, 0x00, 0x00, 0x05, 0x00,
		  0x0B, 0x00, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x16,
		  0x30, 0x16, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x78, 0x57,
		  0x34, 0x12, 0x34, 0x12, 0xCD, 0xAB, 0xEF, 0x00,
		  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C,
		  0xc9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10,
		  0x48, 0x60, 0x02, 0x00, 0x00, 0x00);	  
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 if(!r)return(FALSE);
 if(ord(r[9])==0)return(r);
 else return(FALSE);
}


function lsa_unicode(data)
{
 len = strlen(data);
 ret = raw_string(ord(data[0]));
 
 for(i=1;i<len;i=i+1)
 {
  ret = ret + raw_string(0, ord(data[i]));
 }
 
 
 if(!(len & 1)){even = 1;}
 else even = 0;
 

 if(even)
  {
  ret = ret + raw_string(0,0,0,0xC9, 0x11, 0x18);
  }
 else
  ret = ret + raw_string(0,0,0,0x18);
 
 for(i=0;i<19;i=i+1)
  ret = ret + raw_string(0);
  
 return(ret);
}




#-----------------------------------------------------------------#
# First step : we do _some_ request and we are returned a magic   #
# number that we will use in step 2                               #
#                                                                 #
# (things are starting to get complicated)                        #
#                                                                 # 
#-----------------------------------------------------------------#

function pipe_request_lsa_open_policy_step1(soc, uid, tid, pipe, name)
{
 
 tid_low = tid % 256;
 tid_high = tid / 256;
 
 uid_low = uid % 256;
 uid_high = uid / 256;
 
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 
 
 uc= lsa_unicode(data:tolower(name));
 tot_len = 136 + strlen(uc);
 
 data_count = 60 + strlen(uc);
 data_count_low  = data_count % 256;
 data_count_high = data_count / 256;
 
 
 len = strlen(name) + 3;

 len_low = len % 256;
 len_high = len / 256;
 
 total_data_count = 60 + strlen(uc); 
 total_data_count_low = total_data_count % 256;
 total_data_count_high = total_data_count / 256;
 tot_len_low = tot_len % 256;
 tot_len_high = tot_len / 256;
 bcc = 69 + strlen(uc);
 bcc_low = bcc % 256;
 bcc_high = bcc / 256;
 
 x =  36 + strlen(uc);
 x_low = x % 256;
 x_high = x / 256;
 
 y= 116 + strlen(uc);
 y_low = y % 256;
 y_high = y / 256;
 
 h = raw_string(0x00, 0x00, 
 		  tot_len_high, tot_len_low, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x00, 0x50, 0x81,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_low, tid_high,  0x00, 0x28, uid_low, uid_high,
		  0x00, 0x00, 0x10, 0x00, total_data_count_high, total_data_count_low, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4C,
		  total_data_count_high, total_data_count_low, 0x00, 0x4C, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, bcc_low, bcc_high, 0x5C, 0x50, 0x49,
		  0x50, 0x45, 0x5C, 0x00, 0x00, 0x00, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, total_data_count_high, total_data_count_low, 0x00, 
		  0x00, 0x00, 0x01, 0x00, 0x00, 0x00, x_low, x_high,
		  0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, y_low, 0x34,
		  0x13, 0x00, len_low, len_high, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, len_low, len_high, 0x00, 0x00, 0x5C, 0x00,
		  0x5C, 0x00) + uc + raw_string(
		  0x64, 0xFB, 0x12, 0x00, 0x0C, 0x00,
		  0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00,
		  0x00, 0x02);
		  
 send(socket:soc, data:h);
 r = smb_recv(socket:soc, length:4096);
 if(!r)return(FALSE);
 if(ord(r[9])==0)return(r);
 else return(FALSE);
}


#-------------------------------------------------------------#
# Utility : convert a 4 bytes value to a long 		      #
#-------------------------------------------------------------#			
function long(s, index)
{
 if(index+3 >= strlen(s))return(0);
 num = ord(s[index+3]);
 a = num*256;
 num = ord(s[index+2]);
 num = num + a;
 a = num*256;
 num = ord(s[index+1]);
 num = num+a;
 a = num*256;
 num = ord(s[index]);
 num = num+a;
 return(num);
}


#----------------------------------------------------------#
# Utility : decodes the result of the function step2()     #
#----------------------------------------------------------#
function decode_sid_hex(s)
{
 local_var sid;
 
 
 data_offset = ord(s[52]) * 256;
 data_offset = data_offset + ord(s[51]);
 
 
 pad = 46;	#ord(s[59]);

 index = data_offset + 4 + pad + 6;
 

 name_len = ord(s[index+1]);
 name_len = name_len * 256;
# display("name_len : ", name_len, "\n");

 if(index > strlen(s)) return NULL;
 
 name_len = name_len + ord(s[index]);
 odd = name_len & 1;

 name_len = name_len * 2;
 name_len = name_len + 4;
 name = "";
 
 if(strlen(s) < index + name_len + 11)return NULL;
 
 for(i=4;i<name_len;i=i+2)
 {
  name = name + raw_string(ord(s[index+i]));
 }
 index = index + i + 11;
 if(odd)index = index + 2;
 
 sid = NULL;
 sid = raw_string(0, ord(s[index]));
 index = index + 1;
 for(i=0;i<16;i++)sid += s[i+index];
 return(sid);
}


function decode_sid(s)
{
 data_offset = ord(s[52]) * 256;
 data_offset = data_offset + ord(s[51]);
 

 
 pad = 46;	#ord(s[59]);

 index = data_offset + 4 + pad + 6;
 if(index + 2 > strlen(s))return(NULL);

 name_len = ord(s[index+1]);
 
 name_len = name_len * 256;
# display("name_len : ", name_len, "\n");
 name_len = name_len + ord(s[index]);
 
 
 
 
 odd = name_len & 1;

 name_len = name_len * 2;
 name_len = name_len + 4;
 name = "";
 
 if(strlen(s) < name_len +  index ) return NULL;
 
 for(i=4;i<name_len;i=i+2)
 {
  name = name + raw_string(ord(s[index+i]));
 }
 

  
  
 index = index + i + 11;
 if(odd)index = index + 2;
 
 
 sid = "";
 
 if(index > strlen(s))return NULL;
 sid = string(ord(s[index]), "-");
 index = index + 1;
 
  
 
 num = long(s:s, index:index);
 sid = string(sid, num, "-");
 index = index+4;
 num = long(s:s, index:index);
 sid = string(sid, num, "-");
 index = index+4;
 num = long(s:s, index:index);
 sid = string(sid, num, "-");
 index = index+4;
 num = long(s:s, index:index);
 sid = string(sid, num);
 
 sid = string(name, " : ", sid); 
 return(sid);
 
}			


#-----------------------------------------------------------------------#
# This function requests the sid                                        #
#-----------------------------------------------------------------------#

function pipe_request_lsa_open_policy_step2(soc, uid, tid, pipe, name, reply)				
{

 
 tid_low = tid % 256;
 tid_high = tid / 256;
 
 uid_low = uid % 256;
 uid_high = uid / 256;
 
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 
 

  req = raw_string(0x00, 0x00,
  		  0x00, 0x7A, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x00, 0xC2, 0x80,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_low, tid_high, 0x00, 0x00, uid_low, uid_high,
		  0x00, 0x00, 0x10, 0x00, 0x00, 0x2E, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4C,
		  0x00, 0x2E, 0x00, 0x4C, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, 0x37, 0x00, 0x5C, 0x50, 0x49,
		  0x50, 0x45, 0x5C, 0x00, 0x00, 0x00, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x2E, 0x00,
		  0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x16, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x07, 0x00);
	
  magic = raw_string(ord(reply[84]));		  
  for(i=1;i<20;i=i+1)
  {
   magic = magic + raw_string(ord(reply[84+i]));
  }
  
  req = req + magic + raw_string(0x03, 0x00);
 
  send(socket:soc, data:req);
  r = smb_recv(socket:soc, length:4000);
  return(r);  
}

	 
		 
#---------------------------------------------------------------------#
# Here is our main()                                                  #
#---------------------------------------------------------------------#


name = kb_smb_name();
if(!name)exit(0);


if(!get_port_state(port))exit(0);

login = kb_smb_login();
pass  = kb_smb_password();

if(!login)login = "";
if(!pass) pass = "";

dom = kb_smb_domain();
	  
soc = open_sock_tcp(port);
if(!soc)exit(0);
#
# Request the session
# 
r = smb_session_request(soc:soc,  remote:name);
if(!r)exit(0);

#
# Negociate the protocol
#
prot = smb_neg_prot(soc:soc);
if(!prot)exit(0);

#
# Set up our session
#
r = smb_session_setup(soc:soc, login:login, password:pass, domain:dom, prot:prot);
if(!r)exit(0);
# and extract our uid
uid = session_extract_uid(reply:r);

#
# Connect to the remote IPC and extract the TID
# we are attributed
#      
r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
# and extract our tree id
tid = tconx_extract_tid(reply:r);


#
# Create a pipe to lsarpc
#
r = smbntcreatex_lsarpc(soc:soc, uid:uid, tid:tid);
if(!r)exit(0);
# and extract its ID
pipe = smbntcreatex_extract_pipe(reply:r);

#
# Setup things
#
r = pipe_request_lsa_open_policy_setup(soc:soc, uid:uid, tid:tid, pipe:pipe);
if(!r)exit(0);

#
# Get the magic number
#
r = pipe_request_lsa_open_policy_step1(soc:soc, uid:uid, tid:tid, pipe:pipe,name:name);
if(!r)exit(0);

#
# Get the SID
#
r = pipe_request_lsa_open_policy_step2(soc:soc, uid:uid, tid:tid,
				   pipe:pipe,name:name, reply:r);

if(!r)exit(0);
close(soc);


#
# Woowoo
#
domain_sid = decode_sid(s:r);
domain_sid_hex = decode_sid_hex(s:r);

if( "0-0-0-0-0" >< domain_sid ) exit(0);


if(strlen(domain_sid_hex) != 0)
{
set_kb_item(name:"SMB/domain_sid", value:domain_sid);
set_kb_item(name:"SMB/domain_sid_hex", value:hexstr(domain_sid_hex));
str = string("The domain SID can be obtained remotely. Its value is :\n\n",
	           domain_sid, "\n\n",
              "An attacker can use it to obtain the list of the local users of this host\n",
	      "Solution : filter the ports 137 to 139 and 445\n",
	      "Risk factor : Low\n");
security_warning(data:str, port:port);
}
