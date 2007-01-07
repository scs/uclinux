#
# This script was written by John Lampe ... j_lampe@bellsouth.net
#
# Script is based on wpoison by M.Meadele mm@bzero.net
# See http://wpoison.sourceforge.net
#
# See the Nessus Scripts License for details
#
#



if(description)
{
 script_id(11139);
 script_version ("$Revision: 1.11 $");
 name["english"] = "wpoison (nasl version)";
 script_name(english:name["english"]);
 
 desc["english"] = "
This script attempts to use SQL injection techniques on CGI scripts
More info at : http://www.securiteam.com/securityreviews/5DP0N1P76E.html


Solution : Modify the relevant CGIs so that they properly escape arguments.
Risk factor : Serious";



 script_description(english:desc["english"]);
 
 summary["english"] = "Some common SQL injection techniques";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 John Lampe...j_lampe@bellsouth.net");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

single_quote = raw_string(0x27);

poison[0] = single_quote + "UNION" + single_quote;
poison[1] = single_quote;
poison[2] = single_quote + "%22";
poison[3] = "9%2c+9%2c+9";
poison[4] = single_quote + "bad_bad_value";
poison[5] = "bad_bad_value" + single_quote;
poison[6] = single_quote + "+OR+" + single_quote;
poison[7] = single_quote + "WHERE";
poison[8] = "%3B"; # semicolon
poison[9] = single_quote + "OR";
# methods below from http://www.securiteam.com/securityreviews/5DP0N1P76E.html
poison[10] = single_quote + " or 1=1--";
poison[11] = " or 1=1--";
poison[12] = single_quote + " or " + single_quote + "a" + single_quote + "=" + single_quote + "a";
poison[13] = single_quote + ") or (" + single_quote + "a" + single_quote + "=" + single_quote + "a";


posreply[0] = "Can't find record in";
posreply[1] = "Column count doesn't match value count at row";
posreply[2] = "error " + single_quote;
posreply[3] = "Incorrect column name";
posreply[4] = "Incorrect column specifier for column";
posreply[5] = "Invalid parameter type";
posreply[6] = "Microsoft OLE DB Provider for ODBC Drivers error";
posreply[7] = "ODBC Microsoft Access Driver";
posreply[8] = "ODBC SQL Server Driver";
posreply[9] = "supplied argument is not a valid MySQL result";
posreply[10] = "Table ";
posreply[11] = "Unknown table";
posreply[12] = "You have an error in your SQL syntax";
posreply[13] = "Microsoft VBScript runtime";
posreply[14] = "Syntax";


port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);
unsafe_urls = "";
mywarningcount = 0;


name = string("www/", port, "/cgis");
cgi = get_kb_item(name);

if(!cgi)exit(0);


        # populate two arrays param[] and data[]  
        ptri=coun=0;
  temp = temp2 = "";
  while (cgi && (coun < 50) ) {                     #only gonna deal with up to 50 parameters...sorry
      ptr = strstr(cgi, " ");
      temp = cgi - ptr;
      if (strstr(temp, "[")) {
            for (t=1; t < strlen(temp) - 1; t = t + 1) {
                temp2 = string(temp2,temp[t]);
          }
          data[ptri - 1] = temp2;
      } else {
                param[ptri] = temp;
          ptri = ptri + 1;
      }
      temp = temp2 = "";
      cgi = ptr;
      if(strlen(ptr) > 1)ptr = substr(ptr, 1, strlen(ptr));
      else ptr = NULL;
      cgi = ptr;
      coun = coun + 1;
        }



    for (z=2; param[z]; z = z + 1) {
      for (poo=0; poison[poo]; poo = poo + 1) {
        url = string(param[0],"?");
        for (i=2 ; param[i]; i = i + 1) {
      if (i == z) {
          if (data[i]) {
        url = string(url,param[i],"=",poison[poo]);
          } else {
              url = string(url,param[i],"=",poison[poo]);
          }
      } else {
          if (data[i]) {
              url = string(url,param[i],"=",data[i]);
          } else {
              url = string(url,param[i],"=");
          }
      }
      if (param[i + 1]) {url = string(url,"&");}
        }
        
        
	req = http_get(item:url, port:port);
	inbuff = http_keepalive_send_recv(port:port, data:req);
	if( inbuff == NULL ) exit(0);
        for (mu=0; posreply[mu]; mu = mu + 1) {
            if (egrep(string:inbuff, pattern:posreply[mu])) {
          unsafe_urls = string(unsafe_urls, url, "\n");
          mywarningcount = mywarningcount + 1;
      }
        }
      }
    }


    if (mywarningcount > 0) {
        report = string("
The following URLs seem to be vulnerable to various SQL injection
techniques : \n\n", 
		unsafe_urls,
		"\n\n
An attacker may exploit this flaws to bypass authentication
or to take the control of the remote database.


Solution : Modify the relevant CGIs so that they properly escape arguments
Risk Factor : Serious
See also : http://www.securiteam.com/securityreviews/5DP0N1P76E.html");

        
        security_hole(port:port, data:report);
    }

