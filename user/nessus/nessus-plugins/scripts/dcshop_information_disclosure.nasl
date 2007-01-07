#
# Copyright 2000 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#

desc_english_a = "We detected a vulnerable version of the DCShop CGI. 
This version does not properly protect user and credit card information.
It is possible to access files that contain administrative passwords, 
current and pending transactions and credit card information (along with name, 
address, etc).

The following files are affected:

";

desc_english_b = "
Solution: 
1. Rename following directories to something hard to guess:
 - Data
 - User_carts
 - Orders
 - Auth_data

2. Make these changes to dcshop.setup and dcshop_admin.setup. 

- In dcshop.setup, modify:

$datadir = '$cgidir/Data'
$cart_dir = '$cgidir/User_carts'
$order_dir = '$cgidir/Orders'

- In dcshop_admin.setup, modify:

$password_file_dir = '$path/Auth_data'

3. Rename dcshop.setup and dcshop_admin.setup to something difficult to guess.
For example, dcshop_4314312.setup and dcshop_admin_3124214.setup

4. Edit dcshop.cgi, dcshop_admin.cgi, and dcshop_checkout.cgi and modify the 
require statement for dcshop.setup and dcshop_admin.setup. That is:

- In dcshop.cgi, modify

require '$path/dcshop.setup'

so that it uses new setup file. For example,

require '$path/dcshop_4314312.setup'

- In dcshop_admin.cgi, modify

require '$path/dcshop.setup'
require '$path/dcshop_admin.setup'

so that it uses new setup file. For example,

require '$path/dcshop_4314312.setup'
require '$path/dcshop_admin_3124214.setup'

- In dcshop_checkout.cgi, modify

require '$path/dcshop.setup'

so that it uses new setup file. For example,

require '$path/dcshop_4314312.setup'

5. Save following file as index.html and upload it to your 
/cgi-bin/dcshop directory, thereby hiding directory listing. On 
NT servers, you may have to rename this file to default.htm.

http://www.dcscripts.com/FAQ/

This page show 'Internal Server Error' so it is not an error page...
it's just an index.html file to HIDE directories.

6. Replace your current files with above files

Risk factor : High

Additional information:
http://www.securiteam.com/unixfocus/5RP0N2K4KE.html
";

if(description)
{
 script_id(10718); 
 script_cve_id("CAN-2001-0821");
 script_bugtraq_id(2889);
 script_version ("$Revision: 1.17 $");

 name["english"] = "DCShop exposes sensitive files";
 script_name(english:name["english"]);

 script_description(english:string(desc_english_a, desc_english_b));

 summary["english"] = "DCShop exposes sensitive files";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;
if(!get_port_state(port))exit(0);

gdirs = make_list("", cgi_dirs(), "/dcshop", "/DCshop");
 
program[0] = "/dcshop.pl";
program[1] = "/dcshop.cgi";

orders[0] = "/Orders/orders.txt";
orders[1] = "/orders/orders.txt";

Auth[0] = "/Auth_data/auth_user_file.txt";
Auth[1] = "/auth_data/auth_user_file.txt";

unsafe_url_count = 0;


foreach dir (gdirs)
{
 for (j = 0; program[j] ; j = j + 1)
 {
  url = string(dir, program[j]);
  if (is_cgi_installed_ka(item:url, port:port))
  {
   unsafe_url_count = 0;
   display("Found dcshop at: ", url, "\n");
   for (k = 0; orders[k] ; k = k + 1)
   {
    orders_url = string(dir, orders[k]);
    success = is_cgi_installed_ka(item:orders_url, port:port);
    if (success)
    {
     unsafe_urls[unsafe_url_count] = string("DCShop orders file: ", orders_url);
     unsafe_url_count = unsafe_url_count + 1;
    }
   }
  
   flag = 0;
   for (k = 0; Auth[k]; k = k + 1)
   {
    auth_url = string(dir, Auth[k]);
    success = is_cgi_installed_ka(item:auth_url, port:port);
    if (success)
    {
     flag = 1;
     unsafe_urls[unsafe_url_count] = string("DCShop authentication file: ", auth_url);
     unsafe_url_count = unsafe_url_count + 1;
    }
   }
  }
 }
}

if(unsafe_url_count > 0)
{
  data = desc_english_a;
  for(i = 0; i < unsafe_url_count; i = i + 1)
    data = string(data, unsafe_urls[i], "\n");
  data = string(data, desc_english_b);
  security_hole(port:port, data:data);
}

