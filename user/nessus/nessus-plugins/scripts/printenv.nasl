#
# Copyright 2000 by Hendrik Scholz <hendrik@scholz.net>
#

if(description)
{
 script_id(10188);
 script_version ("$Revision: 1.10 $");
 name["english"] = "printenv";
 script_name(english:name["english"]);
 
 desc["english"] = "The 'printenv' CGI is installed.
printenv normally returns all environment variables.

This gives an attacker valuable information about the
configuration of your web server.

Solution : Remove it from /cgi-bin.

Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/printenv";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Hendrik Scholz");

 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

cgi = "printenv";
port = is_cgi_installed(cgi);
if(port)security_warning(port);

