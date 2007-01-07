#
# (C) Renaud Deraison 
#

if (description)
{
	script_id(11563);
 	script_version ("$Revision: 1.3 $");
 	script_bugtraq_id(7453);
	script_cve_id("CAN-2003-0222");
	script_name(english: "Oracle LINK overflow");
	script_description(english:"
The remote Oracle Database, according to its version number,
is vulnerable to a buffer overflow in the query CREATE DATABASE LINK.

An attacker with a database account may use this flaw to gain the control
on the whole database, or even to obtain a shell on this host.

Solution : See http://otn.oracle.com/deploy/security/pdf/2003alert54.pdf
Risk Factor : High");

	script_summary(english: "Checks the version of the remote Database");

	script_category(ACT_GATHER_INFO);
	script_family(english: "Gain a shell remotely");
	script_copyright(english: "This script is (C) 2003 Renaud Deraison");
	script_dependencie("oracle_tnslsnr_version.nasl");
	script_require_ports(1521, 1541);
	exit(0);
}


port = 1521;
version = get_kb_item("oracle_tnslsnr/1521/version");
if(!version){version = get_kb_item("oracle_tnslsnr/1541/version"); port = 1541; }
if(!version)exit(0);

if(ereg(pattern:".*Version ([0-7]\.|8\.0\.[0-6]|8\.1\.[0-7]|9\.0\.[0-1]|9\.2\.0\.[0-2]).*", string:version))security_hole(port);
