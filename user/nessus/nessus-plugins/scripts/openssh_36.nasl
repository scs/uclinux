#
# (C) Tenable Network Security
#
#
# Thanks to H D Moore for his notification.
#

if(description)
{
 script_id(11837);
 script_bugtraq_id(8628);
 script_cve_id("CAN-2003-0693", "CAN-2003-0695");
 script_version ("$Revision: 1.9 $");

 
 name["english"] = "OpenSSH < 3.7.1";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running a version of OpenSSH which is older than 3.7.1

Versions older than 3.7.1 are vulnerable to a flaw in the buffer management
functions which might allow an attacker to execute arbitrary commands on this 
host.

An exploit for this issue is rumored to exist.


Note that several distribution patched this hole without changing
the version number of OpenSSH. Since Nessus solely relied on the
banner of the remote SSH server to perform this check, this might
be a false positive.

If you are running a RedHat host, make sure that the command :
          rpm -q openssh-server
	  
Returns :
	openssh-server-3.1p1-13 (RedHat 7.x)
	openssh-server-3.4p1-7  (RedHat 8.0)
	openssh-server-3.5p1-11 (RedHat 9)

Solution : Upgrade to OpenSSH 3.7.1
See also : http://marc.theaimsgroup.com/?l=openbsd-misc&m=106375452423794&w=2
	   http://marc.theaimsgroup.com/?l=openbsd-misc&m=106375456923804&w=2
Risk factor : High";
	

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 summary["francais"] = "Vérifie la version de SSH";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#


port = get_kb_item("Services/ssh");
if(!port)port = 22;

key = string("ssh/banner/", port);
banner = get_kb_item(key);


if(!banner)
{
  if(get_port_state(port))
  {
    soc = open_sock_tcp(port);
    if(!soc)exit(0);
    banner = recv_line(socket:soc, length:1024);
    banner = tolower(banner);
    close(soc);
  }
}

if(!banner)exit(0);
banner = tolower(banner);

banner = banner - string("\r\n");
banner = tolower(banner);
if("openssh" >< banner)
{
#always exceptions FreeBSD patched it:(the DATE is important, not patch level)
# see
#HEAD                         OpenSSH_3.6.1p1 FreeBSD-20030916
#RELENG_4                     OpenSSH_3.5p1 FreeBSD-20030916
#RELENG_5_1                   OpenSSH_3.6.1p1 FreeBSD-20030916
#RELENG_4_8                   OpenSSH_3.5p1 FreeBSD-20030916
#RELENG_4_7                   OpenSSH_3.4p1 FreeBSD-20030916
#RELENG_4_6                   OpenSSH_3.4p1 FreeBSD-20030916
#RELENG_4_5                   OpenSSH_2.9 FreeBSD localisations 20030916
#RELENG_4_4                   OpenSSH_2.3.0 FreeBSD localisations 20030916
#RELENG_4_3                   OpenSSH_2.3.0 green@FreeBSD.org 20030916
#sample banner: 4_8
#SSH-2.0-OpenSSH_3.5p1 FreeBSD-20030201
 if(ereg(pattern:".*openssh.*freebsd.*(200309[0-9][0-9]|200[4-9].*)$", string:banner))exit(0);
 if(ereg(pattern:".*openssh[-_](([12]\..*)|(3\.[0-6].*)|(3\.7[^\.]*$))[^0-9]*", string:banner))
	security_hole(port);
}
