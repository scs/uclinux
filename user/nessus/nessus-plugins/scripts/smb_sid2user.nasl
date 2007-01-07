#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(10399);
script_cve_id("CVE-2000-1200");
 script_bugtraq_id(959);
 script_version ("$Revision: 1.42 $");
 
 name["english"] = "SMB use domain SID to enumerate users";
 name["francais"] = "Usage du SID du domaine pour obtenir les noms d'utilisateurs";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "

This script uses the Domain SID to enumerates
the users ID from 1000 to 1200 (or whatever you
set this to, in the preferences)

Risk factor : Medium";

 desc["francais"] = "

Ce script utilise le SID du domaine pour énumerer
les utilisateurs d'id 1000 à 1200 (ou quoi que vous mettiez,
dans les preferences)";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Enumerates users";
 summary["francais"] = "Enumeration des utilisateurs";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000, 2001 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl",
		     "smb_dom2sid.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/domain_sid");
 script_require_ports(139, 445);
 script_add_preference(name:"Start UID : ", type:"entry", value:"1000");
 script_add_preference(name:"End UID : ", type:"entry", value:"1200");
 
 exit(0);
}

include("smb_nt.inc");
port = kb_smb_transport();
if(!port)port = 139;
if(!get_port_state(port))exit(0);
__start_uid = script_get_preference("Start UID : ");
__end_uid   = script_get_preference("End UID : ");

if(__end_uid < __start_uid)
{
 t  = __end_uid;
 __end_uid = __start_uid;
 __start_uid = t;
}

if(!__start_uid)__start_uid = 1000;
if(!__end_uid)__end_uid = __start_uid + 1000;

# 
# Let's go.
#
# This code is long and somehow complex
#







#==================================================================#
# Section 1. Utilities                                             #
#==================================================================#



#-------------------------------------------------------------#
# return a 28 + strlen(data) + (odd(data)?0:1) long string    #
#-------------------------------------------------------------#
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



#-------------------------------------------------------------#
# convert a 4 bytes value to a long 		      #
#-------------------------------------------------------------#			
function long(s, index)
{
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

#---------------------------------------------------------#
# hexstr() to raw_string() conversion			  #
#---------------------------------------------------------#

function hexsid_to_rawsid(s)
{
 local_var i, j, ret;
 
 for(i=0;i<strlen(s);i+=2)
 {
  if(ord(s[i]) >= ord("0") && ord(s[i]) <= ord("9"))
  	j = int(s[i]);
  else
  	j = int((ord(s[i]) - ord("a")) + 10);

  j *= 16;
  if(ord(s[i+1]) >= ord("0") && ord(s[i+1]) <= ord("9"))
  	j += int(s[i+1]);
  else
  	j += int((ord(s[i+1]) - ord("a")) + 10);
  ret += raw_string(j);
 }
 return ret;
}

#---------------------------------------------------------#
# Decode the username we got                              #
#---------------------------------------------------------#
function decode_username(s)
{
 data_offset = ord(s[52]) * 256;
 data_offset = data_offset + ord(s[51]);
 
 pad = ord(s[59]);
 
 
 index = data_offset + 4; 
 mac_len = ord(s[125]);
 mac_len = mac_len * 256;
 mac_len = mac_len + ord(s[124]);

 index = index + mac_len + mac_len + 2 + 130;
 
 odd = mac_len & 1;

 if(odd)index = index + 2;

 name_len = ord(s[index+1]);
 name_len = name_len * 256;
 
 name_len = name_len + ord(s[index]);

 name_len = name_len * 2;
 if(!name_len)return(FALSE);
 name = "";
 index = index+4;
 for(i=0;i<name_len;i=i+2)
 {
  name = string(name,raw_string(ord(s[index+i])));
 }
 return(name);
}			





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
 if(strlen(r) < 10 )return(FALSE);
 if(ord(r[9])==0x00)return(r);
 else return(FALSE);
}





#---------------------------------------------------------#
# Do something that we need for the rest                  #
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
 if(strlen(r) < 10 )return(FALSE);
 if(ord(r[9])==0)return(r);
 else return(FALSE);
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
 tot_len = 132 + strlen(uc);
 
 data_count = 60 + strlen(uc);
 data_count_low  = data_count % 256;
 data_count_high = data_count / 256;
 
 
 len = strlen(name) + 1;

 len_low = len % 256;
 len_high = len / 256;
 
 total_data_count = 56 + strlen(uc); 
 total_data_count_low = total_data_count % 256;
 total_data_count_high = total_data_count / 256;
 tot_len_low = tot_len % 256;
 tot_len_high = tot_len / 256;
 bcc = 65 + strlen(uc);
 bcc_low = bcc % 256;
 bcc_high = bcc / 256;
 
 x =  32 + strlen(uc);
 x_low = x % 256;
 x_high = x / 256;
 
 y= 138 + strlen(uc);
 y_low = y % 256;
 y_high = y / 256;
 
 h = raw_string(0x00, 0x00, 
 		  tot_len_high, tot_len_low, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x00, 0x26, 0x83,
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
		  0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, y_low, 0x48,
		  0x13, 0x00, len_low, len_high, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, len_low, len_high, 0x00, 0x00)
		  + uc + raw_string(
		  0xA4, 0xF2, 
		  0x12, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x02, 0x00, 
		  0x01, 0x00, 0x00, 0x08, 0x00, 0x00);
		  
 send(socket:soc, data:h);
 r = smb_recv(socket:soc, length:4096);
 if(strlen(r) < 10 )return(FALSE);
 if(ord(r[9])==0)return(r);
 else return(FALSE);
}






#-----------------------------------------------------------------------#
# This function requests the name of the user of id <id>                #
#-----------------------------------------------------------------------#




function pipe_request_get_username(soc, uid, tid, pipe, name, reply,id, sid)				
{

 
 tid_low = tid % 256;
 tid_high = tid / 256;
 
 uid_low = uid % 256;
 uid_high = uid / 256;
 
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 
 id_low = id % 256;
 id_high =  id / 256;
 
  
  req = raw_string(0x00, 0x00,
  		  0x00, 0xC4, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x80, ord(reply[16]),ord(reply[17]),
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_low, tid_high, 0x00, 0x00, uid_low, uid_high,
		  0x00, 0x00, 0x10, 0x00, 0x00, 0x6C, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, 0x6C, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, 0x7D, 0x00, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x6C, 0x00,
		  0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x54, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x0F, 0x00);
	
  if(strlen(reply) < 104)return(FALSE);
  magic = raw_string(ord(reply[84]));		  
  for(i=1;i<20;i=i+1)
  {
   magic = magic + raw_string(ord(reply[84+i]));
  }
  
 
  
  req = req + magic + raw_string(0x01, 0x00, 0x00,0x00, 0xD8, 0xF2,
  		0x12, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x3A,
		0x13, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x05,
		0x00, 0x00, 0x00, 0x00) + sid + raw_string( id_low, id_high,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
 
  send(socket:soc, data:req);
  r = smb_recv(socket:soc, length:65000);
  length_answer = ord(r[2]);
  length_answer = length_answer * 256;
  
  if(strlen(r) < 3)return(FALSE);
  length_answer = length_answer + ord(r[3]);
  
  if(strlen(r) < length_answer+3)return(FALSE);
  
  v = ord(r[length_answer+3]);
  if(v==192){
  	return(FALSE);
  	}
  return(r);  
}


#--------------------------------------------------------------#
#  main function to retrieve a username                        #
#--------------------------------------------------------------#
function get_name(soc, uid,tid, pipe, name, id, sid, hdl)
{

#
# Get the SID
#
r = pipe_request_get_username(soc:soc, uid:uid, tid:tid,
				   pipe:pipe,name:name, reply:hdl, id:id, sid:sid);


if(r)
 {
  if(strlen(r) > 125)
  {
  r = decode_username(s:r);
  return(r);
  }
  else return(FALSE);
 }
 else return(FALSE);
}



#==============================================================#
# Section 3. Entry point of the plugin                         #
#==============================================================#



__no_enum = string(get_kb_item("SMB/Users/0"));
if(__no_enum)exit(0);

__no_enum = string(get_kb_item("SMB/Users/1"));
if(__no_enum)exit(0);


# we need the  netbios name of the host
name = kb_smb_name();
if(!name)exit(0);


login = kb_smb_login();
pass  = kb_smb_password();
if(!login)login = "";
if(!pass)pass = "";

domain = kb_smb_domain(); 


# we need the SID of the domain
sidx = get_kb_item("SMB/domain_sid_hex");
if(!sidx)exit(0);

sid = hexsid_to_rawsid(s:sidx);
soc = open_sock_tcp(port);
if(!soc)exit(0);


#
# Request a new session
# 
r = smb_session_request(soc:soc,  remote:name);
if(!r)exit(0);

#
# Negociate the protocol
#
prot = smb_neg_prot(soc:soc);
if(!prot)exit(0);

#
# Set up our null session
#
r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain, prot:prot);
if(!r)exit(0);
# and extract our uid
uid = session_extract_uid(reply:r);

#
# Connect to the remote IPC and extract the TID
# we are attributed
#      
r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
# extract our tree id
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


num_users = 0;
set_kb_item(name:"SMB/Users/enumerated", value:TRUE);
report = string("The domain SID could be used to enumerate the names of the users\n",
		"of this domain. \n",
		"(we only enumerated users name whose ID is between ",
		__start_uid," and ", __end_uid, "\n",
		"for performance reasons)\n",
		"This gives extra knowledge to an attacker, which\n",
		"is not a good thing : \n");
		


#
# Get the magic number
#
lsa = pipe_request_lsa_open_policy_step1(soc:soc, uid:uid, tid:tid, pipe:pipe,name:name);
if(!lsa)exit(0);

		
n = get_name(soc:soc, uid:uid,tid:tid, pipe:pipe, name:name, hdl:lsa, id:500, sid:sid);
if(n)
 {
 num_users = num_users + 1;
 report = report + string("- Administrator account name : ", n, " (id 500)\n");
 set_kb_item(name:string("SMB/Users/", num_users), value:n);
 }

 
 
n = get_name(soc:soc, uid:uid,tid:tid, pipe:pipe, name:name, id:501, hdl:lsa);
if(n)
 {
  report = report + string("- Guest account name : ", n, " (id 501)\n");
  num_users = num_users + 1;
  set_kb_item(name:string("SMB/Users/", num_users), value:n);
 }

#
# Retrieve the name of the users between __start_uid and __start_uid
#
mycounter = __start_uid;
while(1)
{
 n = get_name(soc:soc, uid:uid,tid:tid, pipe:pipe,hdl:lsa, name:name, id:mycounter);
 if(n)
 {
  report = report + string("- ", n, " (id ", mycounter, ")\n");
  num_users = num_users + 1;
  set_kb_item(name:string("SMB/Users/", num_users), value:n);
 }
 else if(mycounter > __end_uid)break;
 
 if(mycounter > (5 * __end_uid))break;
 
 
 mycounter++;
}

close(soc);
report = report + string(
	"\nRisk factor : Medium\n",
	"Solution : filter incoming connections this port\n");

	
if(num_users > 0)
 {
 security_warning(data:report, port:port);
 }
