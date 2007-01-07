#
# DCEMAP
#
# Does a 'portmap-like' request to the remote host, to
# to determine what DCE/MS RPC services are running.
#
# This code is 100% based on 'dcetest', by Dave Aitel, a free (GPL'ed)
# C program available at http://www.immunitysec.com/tools.html
# (or http://www.atstake.com)
#
# NASL translation by Renaud Deraison
# and Pavel Kankovsky, DCIT s.r.o. <kan@dcit.cz>
#
# License: GPLv2
#
# See also:
# CAE Specification, DCE 1.1: Remote Procedure Call, Doc. No. C706
# http://www.opengroup.org/products/publications/catalog/c706.htm
#

if(description)
{
  script_id(10736);
  script_version("$Revision: 1.14 $");

  name["english"] = "DCE Services Enumeration";
  script_name(english:name["english"]);

  desc["english"] = "
Distributed Computing Environment (DCE) services running on the remote host 
can be enumerated by connecting on port 135 and doing the appropriate queries. 

An attacker may use this fact to gain more knowledge
about the remote host.

Solution : filter incoming traffic to this port.
Risk factor : Low";
  script_description(english:desc["english"]);

  summary["english"] = "Enumerates the remote DCE services";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2001 Dave Aitel (ported to NASL by rd and Pavel Kankovsky)");

  family["english"] = "Windows";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes");
  script_require_ports(135);

  exit (0);
}

include("misc_func.inc");

#---------------------------------------------------------------------#

#
# String from a buffer. Inverts the bytes.
#

function istring_from_buffer(b, start, end)
{
  __ret = "";
  for (__i = start; __i <= end; __i = __i + 1)
  {
    __hx = hex(ord(b[__i]));
    __hx = __hx - string("0x");
    # ouch, would drop zeros without string
    __ret = string(__hx, __ret);
  }
  return (__ret);
}

#
# String from a buffer. Straight.
#

function string_from_buffer(b, start, end)
{
  __ret = "";
  for (__i = start; __i <= end; __i = __i + 1)
  {
    __hx = hex(ord(b[__i]));
    __hx = __hx - string("0x");
    # ouch, would drop zeros without string
    __ret = string(__ret, __hx);
  }
  return (__ret);
}

#
# Return the GUID/UUID as something printable
#
# Binary format of UUIDs is as follows:
#   4 bytes  TL (time low)
#   2 bytes  TM (time middle)
#   2 bytes  TH (time high + version)
#   1 byte   CH (clock seq high + reserved)
#   1 byte   CL (clock seq low)
#   6 bytes  NI (node id)
# TL, TM, and TH are interpreted as little endian numbers...
# or (surprise) as big endian numbers depending on the endianness flag
# in PDU header, the location in PDU (header, body), the phase of moon
# and other things; internally, we use LE format.
#
# Text format is as follows:
#   TL-TM-TH-CHCL-NI[0]NI[1]..NI[5]
# where all values are formatted as zero-padded base-16 numbers.
#

function struuid(uuid)
{
  _bTL = istring_from_buffer(b:uuid, start:0, end:3);
  _bTM = istring_from_buffer(b:uuid, start:4, end:5);
  _bTH = istring_from_buffer(b:uuid, start:6, end:7);
  _bCx = string_from_buffer(b:uuid, start:8, end:9);
  _bNI = string_from_buffer(b:uuid, start:10, end:15);
  return (_bTL + "-" + _bTM + "-" + _bTH + "-" + _bCx + "-" + _bNI); 
}

#
# Prepare DCE BIND request
#

function dce_bind()
{ 
  # Endpoint mapper UUID:
  #   E1AF8308-5D1F-11C9-91A4-08002B14A0FA
  ep_uuid = raw_string(
      0x08, 0x83, 0xAF, 0xE1, 0x1F, 0x5D, 0xC9, 0x11,
      0x91, 0xA4, 0x08, 0x00, 0x2B, 0x14 ,0xA0, 0xFA);
  ep_vers = raw_string(0x03, 0x00, 0x00, 0x00);

  # Transfer syntar UUID:
  #   8A885D04-1CEB-11C9-9FE8-08002B104860
  ts_uuid = raw_string(
      0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
      0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60);  
  ts_vers = raw_string(0x02, 0x00, 0x00, 0x00);

  # Request header
  req_hdr = raw_string(
      0x05, 0x00,              # version, minor version
      0x0b, 0x00,              # BINDPACKET, flags
      0x10, 0x00, 0x00, 0x00,  # data representation
      0x48, 0x00,              # fragment length
      0x00, 0x00,              # auth length
      0x01, 0x00, 0x00, 0x00,  # call id
      0x00, 0x10, 0x00, 0x10,  # max xmit frag, max recv frag
      0x00, 0x00, 0x00, 0x00,  # assoc group
      0x01,                    # num ctx items
      0x00, 0x00, 0x00,        # (padding)
      0x00, 0x00,              # p_cont_id
      0x01,                    # n_transfer_syn
      0x00);                   # (padding)

  return (string(
      req_hdr, ep_uuid, ep_vers, ts_uuid, ts_vers));
}

#
# Prepare Endpoint Mapper enumeration request
#

function dce_enum_get_next(callid, handle)
{
  _c0 = callid % 255;

  # Request header
  req_hdr = raw_string(
      0x05, 0x00,              # version, minor version
      0x00, 0x03,              # REQUESTPACKET, flags
      0x10, 0x00, 0x00, 0x00,  # data representation
      0x40, 0x00,              # fragment length
      0x00, 0x00,              # auth length
      _c0,  0x00, 0x00, 0x00,  # call id
      0x00, 0x00, 0x00, 0x00,  # alloc hint
      0x00, 0x00,              # context id
      0x02, 0x00,              # opnum: EPT_LOOKUP
      0x00, 0x00, 0x00, 0x00,  # inquiry_type: RPC_C_EP_ALL_ELTS
      0x00, 0x00, 0x00, 0x00,  # object
      0x00, 0x00, 0x00, 0x00,  # interface_id
      0x00, 0x00, 0x00, 0x00,  # vers_option
      0x00, 0x00, 0x00, 0x00); # entry_handle.attributes

  # Request trailer
  req_tlr = raw_string(
      0x01, 0x00, 0x00, 0x00); # max_ents

  return (string(
      req_hdr, handle, req_tlr));
}

#
# Extract integer values from buffers
#
# These functions should be NASL builtins... :(
#

little_endian = 1;

function load_long(b, t)
{
  if (little_endian) {
    __ret_lo_lo = ord(b[t]);
    __ret_hi_lo = ord(b[t+1]) * 256;
    __ret_lo_hi = ord(b[t+2]) * 65536;
    __ret_hi_hi = ord(b[t+3]) * 16777216;
  }
  else {
    __ret_lo_lo = ord(b[t+3]);
    __ret_hi_lo = ord(b[t+2]) * 256;
    __ret_lo_hi = ord(b[t+1]) * 65536;
    __ret_hi_hi = ord(b[t]) * 16777216;
  }
  __ret = __ret_hi_hi + __ret_lo_hi + __ret_hi_lo + __ret_lo_lo;
  return (__ret);
}

function load_short(b, t)
{
  if (little_endian) {
    __ret_lo = ord(b[t]);
    __ret_hi = ord(b[t+1]) * 256;
  }
  else {
    __ret_lo = ord(b[t+1]);
    __ret_hi = ord(b[t]) * 256;
  }
  __ret = __ret_hi + __ret_lo;
  return (__ret);
}

function load_short_le(b, t)
{
  __ret_lo = ord(b[t]);
  __ret_hi = ord(b[t+1]) * 256;
  __ret  = __ret_hi + __ret_lo;
  return (__ret);
}

function load_short_be(b, t)
{
  __ret_lo = ord(b[t+1]);
  __ret_hi = ord(b[t]) * 256;
  __ret  = __ret_hi + __ret_lo;
  return (__ret);
}

#
# Extract UUID from buffer
#

function load_uuid_le(b, t)
{
  __ret = "";
  for (__i = 0; __i < 16; __i = __i + 1) {
    # ouch, would drop zero bytes without raw_string
    __ret = string(__ret, raw_string(ord(b[t + __i])));
  }
  return (__ret);
}

function load_uuid(b, t)
{
  __ret = "";
  if (little_endian) {
    __ret = load_uuid_le(b:b, t:t);
  }
  else {
    __ret = string(__ret,
	raw_string(ord(b[t + 3])), raw_string(ord(b[t + 2])),
	raw_string(ord(b[t + 1])), raw_string(ord(b[t])),
	raw_string(ord(b[t + 5])), raw_string(ord(b[t + 4])),
	raw_string(ord(b[t + 7])), raw_string(ord(b[t + 6])));
    for (__i = 8; __i < 16; __i = __i + 1) {
      __ret = string(__ret, raw_string(ord(b[t + __i])));
    }
  }
  return (__ret);
}

#
# Extract string from buffer
# Unprintable characters are replaced with ?
#

function load_string(b, t, l)
{
  __ret = "";
  for (__i = 0; __i < l; __i = __i + 1) {
    __c = ord(b[t + __i]);
    if (__c == 0) return (__ret);
    if ((__c < 32) || (__c > 127)) {
      __ret = string(__ret, "?");
    } else {
      __ret = string(__ret, raw_string(__c));
    }
  }
  return (__ret);
}

#
# Parse a response to an enumeration request
#

function dce_parse(result)
{
  # Check whether we got RESPONSEPACKET
  if (ord(result[2]) != 0x02) {
    display("Ouch! received wierd non-response PDU\n");
    return (-1);
  }

  # Update the context handle
  hndatr = load_long(b:result, t:24);
  handle = load_uuid(b:result, t:28);
 
  # Skip:
  #   common DCE header (16 bytes)
  #   alloc_hint, p_cont_id, cancel_count, padding (8 bytes)
  #   context_handle.attributes (4 bytes)
  #   context_handle.uuid (16 bytes)
  #   num_elts (4 bytes) (should check != 0?)
  #   "something" (36 bytes)
  p = 84;

  # Annotation
  tint = load_long(b:result, t:p);
  p = p + 4;
  if (tint > 64) {
    display("Ouch! annotation size too big\n");
    return (-1);
  }
  annotation = load_string(b:result, t:p, l:tint);
  p = p + tint;
  while (p % 4 != 0) p = p + 1;
 
  # Skip tower lengths
  p = p + 8;

  # Number of floors
  floors = load_short_le(b:result, t:p);
  p = p + 2;

  guid = "";
  majver = "???";
  proto = "???";
  ncaproto = "???";
  ncahost = "???";
  ncaport = "???";
  ncaunk = ""; # for undecoded floors

  # Analyze floors
  for (floor = 1; floor <= floors; floor = floor + 1)
  {
    # Sanity check
    if (p >= strlen(result) - 4) {
      display("Ouch! reached end of buffer--malformed PDU?!\n");
      return (-1);
    }

    # Floor part #1 (protocol identifier)
    tint = load_short_le(b:result, t:p);
    p = p + 2;
    addr_type = ord(result[p]);
    addr_data = string_from_buffer(b:result, start:p+1, end:p+tint-2);
    if (floor == 1) {
      # expecting addr_type == 0x0d (UUID_type_identifier), tint == 19
      guid = load_uuid_le(b:result, t:p + 1);
      guid = struuid(uuid:guid);
      majver = load_short_le(b:result, t:p + 17);
    }
    p = p + tint;

    # Floor part #2 (related information)
    tint = load_short_le(b:result, t:p);
    p = p + 2;
    # skip floors 1-3, expected contents:
    #   floor #1: interface UUID (see above)
    #   floor #2: transfer syntax UUID
    #   floor #3: RPC connection-oriented/connectionless
    if (floor > 3) {
      decoded = 0;
      if (addr_type == 0x01) {
        # nonstandard NetBIOS name (string)
        ncahost = "{0x01}" + load_string(b:result, t:p, l:tint);
        decoded = 1;
      }
      if (addr_type == 0x07) {
        # TCP port (2 bytes)
        proto = "tcp";
        ncaproto = "ncacn_ip_tcp:";
        ncaport = load_short_be(b:result, t:p);
        decoded = 1;
      }
      if (addr_type == 0x08) {
        # UDP port (2 bytes)
        proto = "udp";
        ncaproto = "ncadg_ip_udp:";
        ncaport = load_short_be(b:result, t:p);
        decoded = 1;
      }
      if (addr_type == 0x09) {
        # IP address (4 bytes)
        ncahost = string(
            ord(result[p]), ".", ord(result[p+1]), ".",
            ord(result[p+2]), ".", ord(result[p+3]));
        decoded = 1;
      }
      if (addr_type == 0x0f) {
        # named pipe path (string)
        proto = "PIPE";
        ncaproto = "ncacn_np:";
        ncaport = load_string(b:result, t:p, l:tint);
        decoded = 1;
      }
      if (addr_type == 0x10) {
        # LRPC port (string)
        proto = "LRPC";
        ncaproto = "ncalrpc";
        ncahost = "";
        ncaport = load_string(b:result, t:p, l:tint);
        decoded = 1;
      }
      if (addr_type == 0x11) {
        # NetBIOS name (string)
        ncahost = load_string(b:result, t:p, l:tint);
        decoded = 1;
      }
      if (addr_type == 0x16) {
        # Appletalk DSP port (string)
        proto = "APPLE-DSP";
        ncaproto = "ncacn_at_dsp";
        ncaport = load_string(b:result, t:p, l:tint);
        decoded = 1;
      }
      if (addr_type == 0x17) {
        # Appletalk DDP port (string?)
        proto = "APPLE-DDP";
        ncaproto = "ncadg_at_ddp";
        ncaport = load_string(b:result, t:p, l:tint);
        decoded = 1;
      }
      if (addr_type == 0x18) {
        # Appletalk name (string)
        ncahost = load_string(b:result, t:p, l:tint);
        decoded = 1;
      }
      if (addr_type == 0x1f) {
        # HTTP port (2 bytes)
        proto = "tcp";
        ncaproto = "ncacn_http:";
        ncaport = load_short_be(b:result, t:p);
        decoded = 1;
      }
      # seen in the wild, to be identified:
      # - 0x0c (2 bytes)    broken IPX?
      # - 0x0d (10 bytes)   broken IPX? (collision with UUID)
      if (!decoded) {
        ncaunk = string(
            ncaunk, "{", hex(addr_type), "}", addr_data, ":",
            string_from_buffer(b:result, start:p, end:p+tint-1));
      }
    }
    p = p + tint;
  }

  # Found a service
  if (guid) {
    report = report + string(
        "     UUID: ", guid, ", version ", majver, "\n");
    if (proto != "???")
      report = report + string(
        "     Endpoint: ", ncaproto, ncahost, "[", ncaport, "]\n");
    if (ncaunk)
      report = report + string(
        "     Undecoded endpoint data: ", ncaunk, "\n");
    if (annotation)
      report = report + string(
        "     Annotation: ", annotation, "\n");


    if ((proto == "udp") || (proto == "tcp"))
	{
	if(proto == "tcp")
		{
		register_service(port:ncaport, proto:string("DCE/", guid));
		all_report_tcp[ncaport] += report + '\n';
		}
	else
		all_report_udp[ncaport] += report + '\n';
	}
	else all_report_135 += report + '\n';
    return (1);
  }

  return (0);
}

#
# Receive a DCE message
# this is much faster than recv(..., length:4096)
#

function read_dce_pdu(sock)
{
  # Read response header
  __r0 = recv(socket:sock, length:16);

  # Check length
  if (strlen(__r0) != 16) {
    display("Ouch! received ", strlen(__r0), " bytes, expected 16!\n");
    return ("");
  }

  # Check endianness
  if (ord(__r0[4]) & 0xF0 == 0x10)
    little_endian = 1;
  else
    little_endian = 0;

  # Extract fragment length and read the rest
  __r1len = load_short(b:__r0, t:8) - 16;
  __r1 = recv(socket:sock, length:__r1len);

  # Check length
  if (strlen(__r1) != __r1len) {
    display("Ouch! received ", strlen(__r1), " bytes, expected ", __r1len, "!\n");
    return ("");
  }

  # Concatenate the results...the safe way
  __r = "";
  for (__i = 0; __i < 16; __i = __i + 1)
    __r = string(__r, raw_string(ord(__r0[__i])));
  for (__i = 0; __i < __r1len; __i = __i + 1)
    __r = string(__r, raw_string(ord(__r1[__i])));

  return (__r);
}


#---------------------------------------------------------------------#

#
# The main program
#

zero_handle = raw_string
    (0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

handle = zero_handle;
	
if (get_port_state(135))
{	
  all_report_tcp = make_list();
  all_report_udp = make_list();

  soc = open_sock_tcp(135);
  if (!soc) exit(0);
 
  enum = 0;

  send(socket:soc, data:dce_bind());
  r = read_dce_pdu(sock:soc);
  if (strlen(r) < 60) exit(0); # bad reply length

  for (x = 0; x < 4096; x = x + 1)
  {
    send(socket:soc, data:dce_enum_get_next(callid:x, handle:handle));
    r = read_dce_pdu(sock:soc);
    if (strlen(r) <= 65) {
      # finished
      x = 4096;
    }
    else {
      dce_parse(result:r);
      enum = enum + 1;
      if (handle == zero_handle) {
        # finished
        x = 4096;
      }
    }
  }
  close(soc);
  if (enum) security_warning(135);
  
  if(!isnull(all_report_tcp))
  {
  	foreach port (keys(all_report_tcp))
		security_note(port:port, data:'Here is the list of DCE services running on this port:\n' + all_report_tcp[port]);
  }

  if(!isnull(all_report_udp))
  {
  	foreach port (keys(all_report_udp))
		security_note(port:port, data:'Here is the list of DCE services running on this port:\n' + all_report_udp[port], proto:"udp");
 }
  if(all_report_135 != NULL)
	security_note(port:135, data:'Here is the list of DCE services running on this host :\n' + all_report_135);

}

