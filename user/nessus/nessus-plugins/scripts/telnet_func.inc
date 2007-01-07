# -*- Fundamental -*-
#
# (C) 2002 Michel Arboi <arboi@alussinan.org>
# $Revision: 1.7 $

function get_telnet_banner(port)
{
  ___sb = string("telnet/banner/", port);
  ___banner = get_kb_item(___sb);
  if (___banner) return(___banner);

  ___soc = open_sock_tcp(port);
  if(!___soc) return (0);
  ___banner = telnet_init(___soc);
  close(___soc);
  if(strlen(___banner))set_kb_item(name: ___sb, value: ___banner);
  return(___banner);
}

function set_telnet_banner(port, banner)
{
  ___sb = string("telnet/banner/", port);
  set_kb_item(name: ___sb, value: banner);
}
