#
# (C) Tenable Network Security
#
# Ref:
#  Date: Thu, 05 Jun 2003 11:08:44 -0500
#  From: KF <dotslash@snosoft.com>
#  To: bugtraq@securityfocus.com
#  Subject: SRT2003-06-05-0935 - HPUX ftpd remote issue via REST 
#


if(description)
{
 script_id(11701);
 script_version ("$Revision: 1.3 $");
 

 
 name["english"] = "hpux ftpd REST vulnerability";
 
 script_name(english:name["english"]);
             
 desc["english"] = "
The remote FTP server seems to be vulnerable to an integer
conversion bug when it receives a malformed argument to the
'REST' command.

An attacker may exploit this flaw to crash the remote FTP
daemon and possibly execute arbitary code on this host.

Solution : if the remote FTP server is HP/UX ftpd, then
apply patch PHNE_21936.

Risk Factor : High";
                 
               
                     
 script_description(english:desc["english"]);
                    
 
 script_summary(english:"Checks if the remote ftp sanitizes the RETR command");
 script_category(ACT_ATTACK);
 script_family(english:"FTP", francais:"FTP");

 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
                  
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

banner = get_ftp_banner(port:port);
if(banner == NULL)exit(0);

# ProFTPD may seem vulnerable, but actually checks the REST argument
# at download time.
if("ProFTPD" >< banner || "Version wu-" >< banner)exit(0);

if( ! login ) { exit(0); }
soc = open_sock_tcp(port);
if(!soc)exit(0);

if( ftp_log_in(socket:soc, user:login, pass:pass ) ) 
{
 send(socket:soc, data:'REST 1111111111111111\r\n');
 r = recv_line(socket:soc, length:4096);
 ftp_close(socket:soc);
 if("2147483647" >< r ) security_hole(port);
}
