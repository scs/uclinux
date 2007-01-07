# This script was written by Noam Rathaus <noamr@securiteam.com>

if (description)
{
 script_id(10622);
 script_version ("$Revision: 1.9 $");
 script_name(english:"PPTP detection and versioning");
 desc["english"] = "
The remote host seems to be running a PPTP (VPN) service, this service
allows remote users to connect to the internal network and play a trusted
rule in it. This service should be protect with encrypted username
& password combinations, and should be accessible only to trusted
individuals. By default the service leaks out such information as Server
version (PPTP version), Hostname and Vendor string this could help an
attacker better prepare her next attack.

Also note that PPTP is not configured as being cryptographically
secure, and you should use another VPN method if you can


See also : http://www.counterpane.com/pptp-faq.html

Solution: Restrict access to this port from untrusted networks. Make sure
only encrypt channels are allowed through the PPTP (VPN) connection.

Risk factor : Low";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is running a PPTP (VPN) service");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");
 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 script_require_ports(1723);
 exit(0);
}


include("misc_func.inc");

buffer = 
raw_string(0x00, 0x9C) +
# Length

raw_string(0x00, 0x01) +
# Control packet

raw_string(0x1A, 0x2B, 0x3C, 0x4D) +
# Magic Cookie

raw_string(0x00, 0x01) +
# Control Message = Start Session Request

raw_string(0x00, 0x00) +
# Reserved word 1

raw_string(0x01, 0x00) +
# Protocol version = 256

raw_string(0x00) +
# Reserved byte 1

raw_string(0x00) +
# Reserved byte 2

raw_string(0x00, 0x00, 0x00, 0x01) +
# Framing Capability Summary (Can do async PPP)

raw_string(0x00, 0x00, 0x00, 0x01) +	
# Bearer Capability Summary (Can do analog calls)

raw_string(0x00, 0x00) +
# Max Channels

raw_string(0x08, 0x70) +
# Frimware Revision = 2160

raw_string(
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00) +
# Hostname

raw_string(
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00);
# Vendor string

port = 1723;
if (get_port_state(port))
{
 soc = open_sock_tcp(1723);
 if (soc)
 {
  send(socket:soc, data:buffer);
  rec_buffer = recv(socket:soc, length:156);

  # Verify PPTP response

  # Verify PPTP packet
  if ((ord(rec_buffer[2]) == 0) && (ord(rec_buffer[3]) == 1)) # Control Packet
  {
   if ((ord(rec_buffer[8]) == 0) && (ord(rec_buffer[9]) == 2)) # Replay packet
   {

    firmware_version = 0;
    firmware_version = ord(rec_buffer[26])*256 + ord(rec_buffer[27]);

    host_name = "";
    for (i=28; (i<28+64) && (ord(rec_buffer[i]) > 0); i=i+1){
    host_name = host_name + rec_buffer[i];}

    vendor_string = "";
    for (i=92; (i<92+64) && (ord(rec_buffer[i]) > 0); i=i+1){
    vendor_string = vendor_string + rec_buffer[i];}

    buffer = string("A PPTP server is running on this port\n", 
    		     "Firmware Revision:", firmware_version, 
		     "\nHost name:", host_name, 
		     "\nVendor string:", 
		     vendor_string);
    security_note(port:port, data: buffer);
    register_service(port:port, proto:"pptp");
   }
  }
 }
}

