# Fri May 12 15:58:21 GMT 2000
# John Jackson <jjackson@attrition.org>
#
# Test for an "open" X server

# An X server's access control is disabled (e.g. through an "xhost +" command) and 
# allows anyone to connect to the server. 

# proper X11 protocol handling
# by Pavel Kankovsky <kan@dcit.cz>

#
# Changes by rd :
#
# - description
# - minor style issues
# - script_require_ports()
#

if(description)
{
  script_id(10407);
 script_version ("$Revision: 1.20 $");
  script_cve_id("CVE-1999-0526");

  name["english"] = "X Server";
  script_name(english:name["english"]);

  desc["english"] = "
X11 is a client - server protocol. Basically, the server is in charge of the 
screen, and the clients connect to it and send several requests like drawing 
a window or a menu, and the server sends events back to the clients, such as 
mouse clicks, key strokes, and so on...

An improperly configured X server will accept connections from clients from 
anywhere. This allows an attacker to make a client connect to the X server to 
record the keystrokes of the user, which may contain sensitive information,
such as account passwords.

To solve this problem, use xauth or MIT cookies.

Solution : Use xhost, MIT cookies, and filter incoming TCP connections to this 
port.

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "An X Windows System Server is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports(6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009);
 
 script_copyright(english:"This script is Copyright (C) 2000 John Jackson");
 exit(0);
}

#
# The script code starts here
#
function riptext(data, begin, length)
{
  count=begin;
  end=begin+length-1;
  if (end >= strlen(data))
    end = strlen(data) - 1;
  text="";
  for(count=begin;count<=end;count=count+1)
  {
    text = string(text + data[count]);
  }
  return(text);
}

include("misc_func.inc");

####   ##   # ###
# # # #  #  # #  #
# # #  ## # # #  #

#
# The format of client request
#  CARD8    byteOrder (66 'B'=MSB, 108 'l'=LSB)
#  BYTE     padding
#  CARD16   majorVersion, minorVersion
#  CARD16   nBytesAuthProto  (authorization protocol)
#  CARD16   nBytesAuthString (authorization data)
#  CARD     padding
#  STRING8  authProto
#  STRING8  authString
#
# The format of server response:
#  CARD8    success (0=Failed, 1=Success, 2=Authenticate)
#  BYTE     lengthReason (unused if success==1)
#  CARD16   majorVersion, minorVersion (unused if success==2)
#  CARD16   length (of additional data)
#  STRING8  reason (for success==0 or success==1)
#
# CARD16 values are endian-sensitive; endianness is determined by
# the first byte sent by a client
#

# hmm....it might look like a good idea to raise the higher limit to test
# connections forwarded by OpenSSH but it is pointless because OpenSSH
# does not process connections without a cookie--everything you'll get
# will be a stale connection

for(port=6000; port<6010; port++)
{
  if(get_port_state(port))
  { 
    tcpsock = open_sock_tcp(port);
    if(tcpsock)
    {
    xwininfo = raw_string(108,0,11,0,0,0,0,0,0,0,0,0);
    # change the xwininfo bytes above to force servers to send a version mismatch

    send(socket:tcpsock, data:xwininfo);
    tcpresult = recv(socket:tcpsock, length:32);
    close(tcpsock);

    if(tcpresult && strlen(tcpresult) >= 8)
    {
      result = ord(tcpresult[0]);

      if (result == 0) # Failed
          {
            major = ord(tcpresult[2]) + 256 * ord(tcpresult[3]);
            minor = ord(tcpresult[4]) + 256 * ord(tcpresult[5]);
            textresult=riptext(data:tcpresult, begin:8, length:ord(tcpresult[1]));

	    report = string("This X server does *not* allow any client to connect to it\n",
	    	"however it is recommended that you filter incoming connections\n",
		"to this port as attacker may send garbage data and slow down\n",
		"your X session or even kill the server.\n\n",
		"Here is the server version : ", major, ".", minor, "\n",
		"Here is the message we received : ", textresult, "\n\n",
		"Solution : filter incoming connections to ports 6000-6009\n",
		"Risk factor : Low");
            security_warning(port:port, data:report);
	    register_service(port: port, proto: "X11");
          }

      if (result == 1) # Success
          {
            major = ord(tcpresult[2]) + 256 * ord(tcpresult[3]);
            minor = ord(tcpresult[4]) + 256 * ord(tcpresult[5]);
            textresult=riptext(data:tcpresult, begin:40, length:ord(tcpresult[24]));

            report = string("This X server accepts clients from anywhere. This\n",
	    	"allows an attacker to connect to it and record any of your keystrokes.\n\n",
		"Here is the server version : ", major, ".", minor, "\n",
		"Here is the server type : ", textresult, "\n\n",
		"Solution : use xauth or MIT cookies to restrict the access to this server\n",
		"Risk factor : High");
			
	    security_hole(port:port, data:report);	
	    register_service(port: port, proto: "X11");
          }

      if (result == 2) # Authenticate
          {
            textresult=riptext(data:tcpresult, begin:8, length:ord(tcpresult[1]));

	    report = string("This X server does *not* allow any client to connect to it\n",
	    	"however it is recommended that you filter incoming connections\n",
		"to this port as attacker may send garbage data and slow down\n",
		"your X session or even kill the server.\n\n",
		"Here is the message we received : ", textresult, "\n\n",
		"Solution : filter incoming connections to ports 6000-6009\n",
		"Risk factor : Low");
            security_warning(port:port, data:report);
	    register_service(port: port, proto: "X11");
          }

    } #if tcpresult
   } #if tcpsock
  } #if port open
} #for portnum

exit(0);
