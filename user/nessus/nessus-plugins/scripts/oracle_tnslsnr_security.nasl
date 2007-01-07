#
# oracle_tnslsnr_security.nasl - NASL script to do a TNS STATUS 
# command against the Oracle tnslsnr and grep out "SECURITY=OFF"
#
# James W. Abendschan <jwa@jammed.com>
#


if (description)
{
	script_id(10660);
 	script_version ("$Revision: 1.7 $");
	script_name(english: "Oracle tnslsnr security");
	script_description(english: 
"The remote Oracle tnslsnr has no password assigned.
An attacker may use this fact to shut it down arbitrarily,
thus preventing legitimate users from using it properly.

Solution:  use the lsnrctrl SET PASSWORD command to assign a password to, the tnslsnr.
Risk factor : Serious"

	);

	script_summary(english: "Determines if the Oracle tnslsnr has been assigned a password.");

	script_category(ACT_GATHER_INFO);
	script_family(english: "Misc.", francais:"Divers");
	script_copyright(english: "James W. Abendschan <jwa@jammed.com> (GPL)");
	script_dependencie("find_service.nes");
	script_require_ports(1521, 1541);
	exit(0);
}

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
	r = recv(socket:sock, length:8192, timeout:5);

	return (r);
}


function oracle_tnslsnr_security(port)
{
	sock = open_sock_tcp(port);
	if (sock) 
	{
		cmd = "(CONNECT_DATA=(COMMAND=STATUS))";
		reply = tnscmd(sock:sock, command:cmd);

		if ("SECURITY=OFF" >< reply)
		{
			security_hole(port:port);
		}
		else
		{
			if ("SECURITY=ON" >< reply)
			{
				# FYI
				report = string
				(
				"This host is running a passworded Oracle tnslsnr.\n"
				);
				security_note(port:port, data:report);
			}
			else
			{
				# the 3rd, not-likely-but-just-in-case case..
				report = string
				(
"That's odd; the TNS STATUS command didn't include a SECURITY field?",
"\n",
"The reply packet follows:\n", reply, "\n",
"Please report this to jwa@jammed.com\n"
				);
				#display(report);
				# security_warning seems to truncate
				# long strings .. oh well.
				security_note(port:port, data:report);
			}	
		} 
	}	
	close(sock);
}

# tnslsnr runs on different ports . . .

if(get_port_state(1521))
{
	oracle_tnslsnr_security(port:1521);
}

if(get_port_state(1541))
{
	oracle_tnslsnr_security(port:1541);
}

