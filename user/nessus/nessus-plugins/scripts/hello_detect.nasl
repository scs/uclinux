# This plugin was written by Michel Arboi <arboi@alussinan.org>
# It is released under the GNU Public Licence (GPLv2)
#
# See RFC 831 & gated source (hello.h)
# http://www.zvon.org/tmRFC/RFC891/Output/chapter2.html
#

if(description)
{
  script_id(11913);
  script_version ("$Revision: 1.3 $");

  name["english"] = "DCN HELLO detection";
  script_name(english:name["english"]);
 
  desc["english"] = "
This machine is running HELLO. This routing protocol is obsolete and 
should not be used any more.

Risk factor : Low";

  script_description(english:desc["english"]);
 
  summary["english"] = "Sends an DCH HELLO Message";
  script_summary(english:summary["english"]);
  script_category(ACT_GATHER_INFO); 
  script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
  family["english"] = "Misc.";
  family["francais"] = "Divers";
  script_family(english:family["english"], francais:family["francais"]);
  exit(0);
}

#
#                         1                   0 
#               5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
#          --- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# Fixed        |           Checksum            |
# Area         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |             Date              |
#              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |                               |
#              +              Time             +
#              |                               |
#              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |           Timestamp           |
#              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |     Offset    |   Hosts (n)   |
#          --- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# Host         |          Delay Host 0         |
# Area         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |         Offset Host 0         |
#              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#             ...                             ...
#              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |         Delay Host n-1        |
#              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |         Offset Host n-1       |
#          --- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# 
#                Figure 3. HELLO Message Format
# 

include("network_func.inc");
##include("dump.inc");

if (islocalhost()) exit(0); # Would false positive

s = this_host();
v = eregmatch(pattern: "^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9])+$", string: s);
if (isnull(v)) exit(0);

for (i = 1; i <=4; i++) a[i] = int(v[i]);

a1 = rand() % 256; a2 = rand() % 256;
s1 = rand() % 256; s2 = rand() % 256;

# Date is in RT-11 format, i.e. little endian, AFAIK. The date overflows
# in 2003 (!) so I suggest to tell them that we are at 2003-12-31 
# The source of gated gives more information than RFC 891. 2003-12-31 would
# give: 0x33FF; adding flags 0xC000 (Clock is unsynchronized) gives 0xF3FF

ms = ms_since_midnight();		# milliseconds since midnight
if (isnull(ms)) ms = rand();

r = raw_string(
	0, 0, 		# Checksum
	0xF3, 0xFF	# Date
	);
r += htons(ms);		# Time = ms since midnight
r  += raw_string(
	0, 0,		# Timestamp
	0,		# Offset (?)
	0 );		# Nb of hosts ??

ck = ip_checksum(data: r);
r2 = insstr(r, ck, 0, 1);

# HELLO is protocol 63
egp = forge_ip_packet(ip_v: 4, ip_hl: 5, ip_tos: 0, ip_p: 63, ip_ttl: 64,
			ip_off: 0, ip_src: this_host(),	data: r2);

f = "ip proto 63 and src " + get_host_ip();
r = send_packet(egp, pcap_active: TRUE, pcap_filter: f);
if (isnull(r)) exit(0);

##hl = ord(r[0]) & 0xF; hl *= 4;
##hello = substr(r, hl);
##dump(dtitle: "hello", ddata: hello);

#ck = ip_checksum(data: hello);

security_warning(port: 0, proto: "hello");
