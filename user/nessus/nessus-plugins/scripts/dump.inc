# -*- Fundamental -*-
#
# (C) 2002 Georges Dagousset <georges.dagousset@orange.fr>
# $Revision: 1.4 $



function hexdump(ddata)
{
 _z = "";
 __dmaxline = strlen(ddata) / 16;
 for (__dline = 0; __dline <= __dmaxline; __dline = __dline + 1) {
  _z = string(_z, hex(__dline*16),":") -"0x";
  for (__dcol = 0; __dcol < 16; __dcol = __dcol + 1) {
   if (!__dcol % 4) _z = _z + " ";
   if (__dcol + __dline * 16 < strlen(ddata))
    _z = string(_z, hex(ord(ddata[__dcol + __dline * 16]))," ")-"0x";
   else
    _z = _z + "   ";
  }
  _z = _z + "   ";
  for (__dcol = 0; __dcol < 16; __dcol = __dcol + 1) {
   if (__dcol + __dline * 16 < strlen(ddata)) {
    if(ord(ddata[__dcol + __dline * 16]) >= 32)
     _z = _z + ddata[__dcol + __dline * 16];
    else
     _z = _z + ".";
   }
   else
    _z = _z + "   ";
  }
  _z = string(_z, "\n");
 }
 _z = string(_z, "\n");
 return (_z);
}

function dump(ddata,dtitle)
{
 if(dtitle)display(":::",dtitle,"\n");
 display(hexdump(ddata: ddata));
}

