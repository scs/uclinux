# Written by Renaud Deraison <deraison@nessus.org>
#
#
# This plugin uses the data collected by webmirror to display the list
# of files that may not be suitable to be distributed over the web as
# they may be used for intelligence purposes.


if(description)
{
 script_id(11419);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Office files list";
 script_name(english:name["english"]);
 
 desc["english"] = "
This script displays the list of .xls, .ppt, .doc and .pdf files that
are available on the remote server.

Distributing such files over the web can be done, but the webmaster
should make sure that they contain no confidential data.";


 script_description(english:desc["english"]);
 
 summary["english"] = "Displays office files";
 
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl", "webmirror.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


function test_files(files)
{
 local_var f, req, soc, r, retf;
 
 retf = make_list();
 foreach f (files)
 {
  req = http_get(item:f, port:port);
  soc = http_open_socket(port);
 
  if(!soc)exit(0);
  
  send(socket:soc, data:req);
  r  = recv_line(socket:soc, length:4096);
  close(soc);
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:r)){
  	retf = make_list(retf, f);
	}
 }
 return retf;
}


port = get_kb_item("Services/www");
if(!port) port = 80;

if(!get_port_state(port))exit(0);

report = NULL;


t = get_kb_list(string("www/", port, "/content/extensions/doc"));
if(!isnull(t)){
 t = test_files(files:make_list(t));
 word = NULL;
 foreach f (t)
 {
  word += '   ' + f + '\n';
 }
 if( word != NULL ) report += 'The following Word files (.doc) are available on the remote server : \n' + word;
}

t = get_kb_list(string("www/", port, "/content/extensions/xls"));
if(!isnull(t)){
 t = test_files(files:make_list(t));
 xl = NULL;
 foreach f (t)
 {
  xl += '   ' + f + '\n';
 }
 
  if( xl != NULL ) report += 'The following Excel files (.xls) are available on the remote server : \n' + xl;
}


t = get_kb_list(string("www/", port, "/content/extensions/ppt"));
if(!isnull(t)){
 t = test_files(files:make_list(t));
 ppt = NULL;
 foreach f (t)
 {
  ppt += '   ' + f + '\n';
 }
 
 if( ppt != NULL) report += 'The following PowerPoint files (.ppt) are available on the remote server : \n' + ppt;
 
}

t = get_kb_list(string("www/", port, "/content/extensions/pdf"));
if(!isnull(t)){
 t = test_files(files:make_list(t));
 pdf = NULL;
 foreach f (t)
 {
  pdf += '   ' + f + '\n';
 }
 
 if( pdf != NULL )report += 'The following PDF files (.pdf) are available on the remote server : \n' + pdf;
}



if( report != NULL )
{
 report += '
 
You should make sure that none of these files contain confidential or
otherwise sensitive information.

An attacker may use these files to gain a more intimate knowledge of
your organization and eventually use them do perform social engineering
attacks (abusing the trust of the personnel of your company).

Solution : sensitive files should not be accessible by everyone, but only
by authenticated users.';

 security_note(port:port, data:report);
}
