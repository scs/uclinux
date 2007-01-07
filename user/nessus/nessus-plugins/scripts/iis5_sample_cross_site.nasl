#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10572);
 script_version("$Revision: 1.4 $");
 name["english"] = "IIS 5.0 Sample App vulnerable to cross-site scripting attack";
 name["francais"] = "IIS 5.0 Sample App vulnerable to cross-site scripting attack";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The script /iissamples/sdk/asp/interaction/Form_JScript.asp 
(or Form_VBScript.asp) allows you to insert information into a form 
field and once submitted re-displays the page, printing the text you entered.  
This .asp doesn't perform any input validation, and hence you can input a 
string like:
<SCRIPT>alert(document.domain)</SCRIPT>.

More information on cross-site scripting attacks can be found at:

http://www.cert.org/advisories/CA-2000-02.html

Solution: Always remove sample applications from productions servers. 
In this case, remove the entire /iissamples folder.
Risk factor : Low";





 script_description(english:desc["english"]);
 
 summary["english"] = "IIS 5.0 Sample App vulnerable to cross-site scripting attack";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2000 Matt Moore",
		francais:"Ce script est Copyright (C) 2000 Matt Moore");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}

# Check starts here

port = is_cgi_installed("/iissamples/sdk/asp/interaction/Form_JScript.asp");
if(port)security_warning(port);

