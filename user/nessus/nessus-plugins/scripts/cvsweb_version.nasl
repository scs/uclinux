#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
# Changes by rd :
# - script id
# - french desc.
# - more verbose report
# - hole -> warning
# 



if(description)
{
 script_id(10402);
 script_version ("$Revision: 1.14 $");
 
 name["english"] = "CVSWeb detection";
 name["francais"] = "Detection de CVSWeb";
 script_name(english:name["english"], francais:name["francais"]);
 
 
desc["english"] = "
CVSWeb is used by hosts to share programming source 
code. Some web sites are misconfigured and allow access
to their sensitive source code without any password protection. 
This plugin tries to detect the presence of a CVSWeb CGI and
when it finds it, it tries to obtain its version.

Risk factor : Low
Solution : Password protect the CGI if unauthorized access isn't wanted";



desc["francais"] = "
CVSWeb est utilisé pour partager le code source de certains
programmes par le web. Plusieurs sites web sont mal configurés
et permettent à n'importe qui d'avoir accès à ce code source,
sans demander de mot de passe.
Ce plugin determines la présence de cvsweb et essaye d'en obtenir
la version

Facteur de risque : Faible
Solution : protégez par mot de passe the CGI si les accès anonymes ne sont
pas autorisés";
 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks if CVSWeb is present and gets its version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2000 SecuriTeam",
		francais:"Ce script est Copyright (C) 2000 SecuriTeam");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"],
 		francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 req = string(dir, "/cvsweb.cgi/");
 req = http_get(item:req, port:port);
 result = http_keepalive_send_recv(port:port, data:req);
 if( result == NULL ) exit(0);
 if("CVSweb $Revision:" >< result)
  {
   result = strstr(result, string("CVSweb $Revision: "));
   result = result - strstr(result, string(" $ -->\n"));
   result = result - "CVSweb $Revision: ";
   name = string("www/", port, "/cvsweb/version");
   set_kb_item(name:name, value:result);
   result = string(
"\nThe 'cvsweb' cgi is installed.\n",   
"cvsweb is used to browse the content of a CVS repository\n",
"It can be used by an intruder to obtain the source of your\n",
"programs if you keep them secret.\n\n",
"The installed version of this CGI is : ",  result, "\n\n",
"Solution : Restrict the access to this CGI using password protection,\n",
"or disable it if you do not use it\n",
"Risk factor : Low");

   security_warning(port:port, data: result);
   exit(0);
  } 
}
