#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref: 
# From: Stefan Esser <s.esser@e-matters.de>
# Message-ID: <20021212112625.GA431@php.net>
# To: full-disclosure@lists.netsys.com
# Cc: vulnwatch@vulnwatch.org, bugtraq@securityfocus.com
# Subject: [VulnWatch] Advisory 04/2002: Multiple MySQL vulnerabilities
#
# URL:
# http://security.e-matters.de/advisories/042002.html 
#

if(description)
{
 
 script_id(11192);  
 script_version ("$Revision: 1.5 $");
 script_cve_id("CAN-2002-1373", "CAN-2002-1374", "CAN-2002-1375", "CAN-2002-1376");
 script_bugtraq_id(6368, 6370, 6373, 6374, 6375, 8796);
 
 name["english"] = "multiple MySQL flaws";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
You are running a version of MySQL which is 
older than version 3.23.54 or 4.0.6

If you have not patched this version, then
any attacker may crash this service remotely.

See also : http://security.e-matters.de/advisories/042002.html

Solution : Upgrade to the latest version of MySQL
Risk factor : Medium
";

	


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote MySQL version";
 summary["francais"] = "Vérifie la version de MySQL";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "mysql_version.nasl");
 script_require_ports("Services/mysql", 3306);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

port = get_kb_item("Services/mysql");
if(!port)port = 3306;

ver=get_mysql_version(port); 
if(ver==NULL) exit(0);
if(ereg(pattern:"3\.(([0-9]\..*|(1[0-9]\..*)|(2[0-2]\..*))|23\.([0-4][0-9]|5[0-3])[^0-9])",
  	  string:ver))security_hole(port);	  
if(ereg(pattern:"4\.0\.[0-5][^0-9]", string:ver))security_hole(port);	  
