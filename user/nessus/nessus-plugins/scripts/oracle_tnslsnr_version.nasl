#
# oracle_tnslsnr_version - NASL script to do a TNS VERSION command against the
# Oracle tnslsnr
#
# James W. Abendschan <jwa@jammed.com>
#
# modified by Axel Nennker 20020306
#

if (description)
{
	script_id(10658);
 	script_version ("$Revision: 1.17 $");
 script_bugtraq_id(1853);
	script_name(english: "Oracle tnslsnr version query");
	script_description(english: 
	"This script determines the version of the Oracle tnslsnr 
(network listener).  Certain versions of tnslsnr allow intruders
to write arbitrary data to anywhere the tnslsnr has write
permissions (e.g., .rhosts, .forward).  Affected versions
also are subject to denial-of-service attacks which can shut
down or crash the listener.

See also:http://otn.oracle.com/deploy/security/pdf/listener_alert.pdf

Risk factor : High

Solution : Upgrade");

	script_summary(english: "connects to ports 1541 and/or 1521, issues a TNS VERSION command");

	script_category(ACT_GATHER_INFO);
	script_family(english: "Misc.", francais:"Divers");
	script_copyright(english: "James W. Abendschan <jwa@jammed.com> (GPL)");
	script_dependencie("find_service.nes");
	script_require_ports(1521, 1541);
	script_cve_id("CVE-2000-0818");
	exit(0);
}

include("misc_func.inc");

function tnscmd(sock, command)
{
	# construct packet
	
	command_length = strlen(command);
	packet_length = command_length + 58;

	# packet length - bytes 1 and 2

	plen_h = packet_length / 256;
	plen_l = 256 * plen_h;			# bah, no ( ) ?
	plen_l = packet_length - plen_h;

	clen_h = command_length / 256;
	clen_l = 256 * clen_h;
	clen_l = command_length - clen_l;


	packet = raw_string(
		plen_h, plen_l, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
		0x01, 0x36, 0x01, 0x2c, 0x00, 0x00, 0x08, 0x00, 
		0x7f, 0xff, 0x7f, 0x08, 0x00, 0x00, 0x00, 0x01, 
		clen_h, clen_l, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x34, 0xe6, 0x00, 0x00, 
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, command
		);


	send (socket:sock, data:packet);
}

# Reply comes in 2 packets.  The first is the reply to the connection
# request, and if that is successful, the second contains the reply to
# the version request.
#
# The TNS packets come with a 8 byte header and the header contains
# the packet length.  The first 2 bytes of the header are the total
# length of the packet in network byte order.  
#
# Steven Procter, Nov 11 2002

function unpack_short(buf, offset) {
	result = ord(buf[offset]) * 256 + ord(buf[offset + 1]);
	return result;
}

function extract_version(socket) {
	header = recv(socket:socket, length:8, timeout:5);
	if (ord(header[4]) == 4) {
		report = string("A TNS service is running on this port but it\n",
			"refused to honor an attempt to connect to it.\n",
			"(The TNS reply code was ", ord(header[4]), ")");
		security_note(port:port, data:report);
		return 0;
	}
	if (ord(header[4]) != 2) {
		report = "A service other than TNS seems to be running on this port.";
		security_note(port:port, data:report);
		return 0;
	}
	# read the rest of the accept packet
	tot_len = unpack_short(buf:header, offset:0);
	remaining = tot_len - 8;
	rest = recv(socket:sock, length:remaining, timeout:5);
	
	# next packet should be of type data and the data contains the version string
	header = recv(socket:sock, length:8, timeout:5);
	tot_len = unpack_short(buf:header, offset:0);
	# check the packet type code, type Data is 6
	if (ord(header[4]) != 6) {
		report = string("The TNS server refused to respond to a version request.\n",
			"(The TNS reply code was ", packet[4], ")");
		security_note(port:port, data:report);
		return 0;
	}

	# first 2 bytes of the data are flags, the rest is the version string.
	remaining = tot_len - 8;
	flags = recv(socket:sock, length:2, timeout:5);
	version = recv(socket:sock, length:remaining - 2, timeout:5);
	return version;
}

function oracle_version(port)
{
	sock = open_sock_tcp(port);
	if (sock)
	{
		cmd = "(CONNECT_DATA=(COMMAND=VERSION))";
		tnscmd(sock:sock, command:cmd);
		version = extract_version(socket:sock);
		# if you believe Oracle, only 7.3.4, 8.0.6, and 8.1.6 
		# are vulnerable..
		# TNSLSNR for Solaris: Version 8.1.6.0.0 - Production
		register_service(port:port, proto:"oracle_tnslsnr");
		set_kb_item(name:string("oracle_tnslsnr/", port, "/version"),
			    value:version);
		
		if (ereg(pattern:".*.Version\ (8\.1\.6)|(8\.0\.6)|(7\.3\.4).*.", string:version))
		{
			
			report = string("This host is running a buggy version of the Oracle tnslsnr: ",version,"\n",
			"This version of tnslsnr allow intruders\n",
			"to write arbitrary data to anywhere the tnslsnr has write\n",
			"permissions (e.g., .rhosts, .forward).  Affected versions\n",
			"also are subject to denial-of-service attacks which can shut\n",
			"down or crash the listener.\n",
			"Solution : Upgrade\n",
			"See http://otn.oracle.com/deploy/security/pdf/listener_alert.pdf\n",
			"Risk factor : High");				
			security_hole(port:port, data:report);
		}
		else
		{
				report = "This host is running the Oracle tnslsnr: " + version;				
				security_note(port:port, data:report);
		}
	} 
	close(sock);
}

if(get_port_state(1521))
{
 oracle_version(port:1521);
}

if(get_port_state(1541))
{
 oracle_version(port:1541);
}
