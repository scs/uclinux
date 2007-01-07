#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
# HTTP code comes from http_auth.nasl written by Michel Arboi <arboi@alussinan.org>
# NNTP was added by Michel Arboi <arboi@alussinan.org>
#
# See the Nessus Scripts License for details
#

default_http_login = "";
default_http_password = "";

default_nntp_login = "";
default_nntp_password = "";

default_ftp_login = "anonymous";
default_ftp_password = "nessus@nessus.org";
default_ftp_w_dir = "/incoming";

default_pop2_login = "";
default_pop2_password = "";

default_pop3_login = "";
default_pop3_password = "";

default_imap_login = "";
default_imap_password = "";

default_smb_login = "";
default_smb_password = "";
default_smb_domain = "";

default_snmp_community = "";

if(description)
{
 script_id(10870);
 script_version ("$Revision: 1.17 $");
 name["english"] = "Login configurations";
 name["francais"] = "Configuration des logins";
 
 script_name(english:name["english"],
            francais:name["francais"]);
 
 desc["english"] = "
Provide the username/password for the common servers :
 HTTP, FTP, NNTP, POP2, POP3,IMAP and SMB (NetBios).

Some plugins will use those logins when needed.
If you do not fill some logins, those plugins will not be able run.

This plugin does not do any security check.

Risk factor : None";

 desc["francais"] = "
Fournir le nom_d_utilisateur/mot_de_passe pour les serveurs communs :
 HTTP, FTP, NNTP, POP2, POP3, IMAP et SMB (NetBios).

Certains plugins utiliseront ces logins si nécessaire.
Si vous ne remplissez pas certains logins, ces plugins ne pourront pas s exécuter.

Ce plugin ne fait aucun test de securité

Facteur de risque : Aucun";

 script_description(english:desc["english"],
                   francais:desc["francais"]);
 
 summary["english"] = "Logins for HTTP, FTP, NNTP, POP2, POP3, IMAP and SMB";
 summary["francais"] = "Logins pour HTTP, FTP, NNTP, POP2, POP3, IMAP et SMB";
 script_summary(english:summary["english"],
               francais:summary["francais"]);
 
 script_category(ACT_SETTINGS);
 
 script_copyright(english:"This script is Copyright (C) 2002 Georges Dagousset ");
 family["english"] = "Settings";
 family["francais"] = "Configuration";
 script_family(english:family["english"], francais:family["francais"]);
 
 script_add_preference(name:"HTTP account :", type:"entry", value:default_http_login);
 script_add_preference(name:"HTTP password (sent in clear) :", type:"password", value:default_http_password);

 script_add_preference(name:"NNTP account :", type:"entry", value:default_nntp_login);
 script_add_preference(name:"NNTP password (sent in clear) :", type:"password", value:default_nntp_password);

 script_add_preference(name:"FTP account :", type:"entry", value:default_ftp_login);
 script_add_preference(name:"FTP password (sent in clear) :", type:"password", value:default_ftp_password);
 script_add_preference(name:"FTP writeable directory :", type:"entry", value:default_ftp_w_dir);

 script_add_preference(name:"POP2 account :", type:"entry", value:default_pop2_login);
 script_add_preference(name:"POP2 password (sent in clear) :", type:"password", value:default_pop2_password);

 script_add_preference(name:"POP3 account :", type:"entry", value:default_pop3_login);
 script_add_preference(name:"POP3 password (sent in clear) :", type:"password", value:default_pop3_password);

 script_add_preference(name:"IMAP account :", type:"entry", value:default_imap_login);
 script_add_preference(name:"IMAP password (sent in clear) :", type:"password", value:default_imap_password);

 script_add_preference(name:"SMB account :", type:"entry", value:default_smb_login);
 script_add_preference(name:"SMB password :", type:"password", value:default_smb_password);
 script_add_preference(name:"SMB domain (optional) :", type:"entry", value:default_smb_domain);
 if(defined_func("nt_owf_gen"))script_add_preference(name:"Never send SMB credentials in clear text", type:"checkbox", value:"yes");
 if(defined_func("ntv2_owf_gen"))script_add_preference(name:"Only use NTLMv2", type:"checkbox", value:"no");
 script_add_preference(name:"SNMP community (sent in clear) :", type:"entry", value:default_snmp_community);
 exit(0);
}

#
# base64 conversion was written by Renaud Deraison.
#
__base64_code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function base64_code(c)
{
 return(__base64_code[c]);
}

function pow2(x)
{
 __ret = 1;
 while(x)
  {
  __ret = __ret * 2;
  x = x  - 1;
  }
 return(__ret);
}

function base64(str)
{
 len = strlen(str);
 i = 0;
 ret = "";
 char_count = 0;
 _bits = 0;
 while(i < len)
 {
  _bits = _bits + ord(str[i]);
  char_count = char_count + 1;
  if(char_count == 3)
  {
    val = _bits / 262144;
    ret = string(ret, base64_code(c:val));
    val = _bits / 4096;
    val = val & 0x3F;
    ret = string(ret, base64_code(c:val));
    val = _bits / 64;
    val = val & 0x3F;
    ret = string(ret, base64_code(c:val));
    val = _bits & 0x3F;
    ret = string(ret, base64_code(c:val));
    char_count = 0;
    _bits = 0;
 }
 else {
       _bits = _bits * 256;
       }
 i = i + 1;
 }


 if(!(char_count == 0))
 {
  cnt = char_count * 8;
  mul = 16;
  mul = mul - cnt;
  mul = pow2(x:mul);
  _bits = _bits * mul;
  val = _bits / 262144;
  ret = string(ret, base64_code(c:val));
  val = _bits / 4096;
  val = val & 0x3F;
  ret = string(ret, base64_code(c:val));
 if(char_count == 1)
 { 
  ret = string(ret, "==");
 }
 else
 {
   val = _bits / 64;
   val = val & 0x3F;
   ret = string(ret, base64_code(c:val), "=");
  }
 }
 return(ret);
}

# HTTP
http_login = script_get_preference("HTTP account :");
http_password = script_get_preference("HTTP password (sent in clear) :");
if (http_login)
{
 if(http_password)
 {
  set_kb_item(name:"http/login", value:http_login);
  set_kb_item(name:"http/password", value:http_password);

  userpass = string(http_login, ":",http_password);
  #display(userpass);
  userpass64 = base64(str:userpass);
  authstr = "Authorization: Basic " + userpass64;
  set_kb_item(name:"http/auth", value:authstr);
 }
}

# NNTP
nntp_login = script_get_preference("NNTP account :");
nntp_password = script_get_preference("NNTP password (sent in clear) :");
if (nntp_login)
{
 if(nntp_password)
 {
  set_kb_item(name:"nntp/login", value:nntp_login);
  set_kb_item(name:"nntp/password", value:nntp_password);
 }
}

# FTP
ftp_login = script_get_preference("FTP account :");
ftp_password = script_get_preference("FTP password (sent in clear) :");
ftp_w_dir = script_get_preference("FTP writeable directory :");
if (!ftp_w_dir) ftp_w_dir=".";
set_kb_item(name:"ftp/writeable_dir", value:ftp_w_dir);
if(ftp_login)
{
 if(ftp_password)
 {
  set_kb_item(name:"ftp/login", value:ftp_login);
  set_kb_item(name:"ftp/password", value:ftp_password);
 }
}

# POP2
pop2_login = script_get_preference("POP2 account :");
pop2_password = script_get_preference("POP2 password (sent in clear) :");
if(pop2_login)
{
 if(pop2_password)
 {
  set_kb_item(name:"pop2/login", value:pop2_login);
  set_kb_item(name:"pop2/password", value:pop2_password);
 }
}

# POP3
pop3_login = script_get_preference("POP3 account :");
pop3_password = script_get_preference("POP3 password (sent in clear) :");
if(pop3_login)
{
 if(pop3_password)
 {
  set_kb_item(name:"pop3/login", value:pop3_login);
  set_kb_item(name:"pop3/password", value:pop3_password);
 }
}

# IMAP
imap_login = script_get_preference("IMAP account :");
imap_password = script_get_preference("IMAP password (sent in clear) :");
if(imap_login)
{
 if(imap_password)
 {
  set_kb_item(name:"imap/login", value:imap_login);
  set_kb_item(name:"imap/password", value:imap_password);
 }
}

# SMB
smb_login = script_get_preference("SMB account :");
if(!smb_login)smb_login = "";

smb_password = script_get_preference("SMB password :");
if(!smb_password)smb_password = "";

smb_domain = script_get_preference("SMB domain (optional) :");
if(!smb_domain)smb_domain = "";

if(defined_func("nt_owf_gen"))
{
smb_ctxt = script_get_preference("Never send SMB credentials in clear text");
if(!smb_ctxt)smb_ctxt = "yes";
} else smb_ctxt = "no";

if(smb_ctxt == "yes")
 set_kb_item(name:"SMB/dont_send_in_cleartext", value:TRUE);



if(defined_func("ntv2_owf_gen"))
{
 smb_ntv1 = script_get_preference("Only use NTLMv2");
 if(smb_ntv1 == "yes"){
 	set_kb_item(name:"SMB/dont_send_ntlmv1", value:TRUE);
	if(smb_ctxt != "yes")set_kb_item(name:"SMB/dont_send_in_cleartext", value:TRUE);
	}
}


if(smb_login)
{
  set_kb_item(name:"SMB/login_filled", value:smb_login);
}
  
if(smb_password)
{
  set_kb_item(name:"SMB/password_filled", value:smb_password);
}

if(smb_domain)
{ 
 set_kb_item(name:"SMB/domain_filled", value:smb_domain);
}





# SNMP
snmp_community = script_get_preference("SNMP community (sent in clear) :");
if(strlen(snmp_community) > 0 )
{
 set_kb_item(name:"SNMP/community", value:snmp_community);
}
