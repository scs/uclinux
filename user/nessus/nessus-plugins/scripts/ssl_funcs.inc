# (C) 2003 Tenable Network Security
# $Id: ssl_funcs.inc,v 1.1 2003/10/10 21:43:25 renaud Exp $

function client_hello (port, mlen, mtype, version, cspeclen, sessionidlen, challengelen, cipherspec, challenge) {
  # mlen = message length after this byte (1 byte) ... I don't expect user to fill this in...but, you never know ;-)
  # mtype = handshake message type (1 byte)
  # version = SSL 1,2,3 NOTE: this spec was written based on SSL v3 (2 bytes)
  # cspeclen = cipher spec len (2 bytes)
  # sessionidlen = session ID length (2 bytes)
  # challengelen = length of challenge (2 bytes)
  # cipherspec = which ciphers are supported (defaults to 21 bytes, unless changed)
  # challenge = random bytes of challenge data


  # OK, what did they pass me...

  if (!mtype) mtype = raw_string(0x01);

  if (!version) version = raw_string(0x03, 0x00);

  if (!sessionidlen) sessionidlen = raw_string(0x00, 0x00);

  if (!cipherspec) cipherspec = raw_string(0x00, 0x00, 0x62);
  cipherspec += raw_string(0x00, 0x00, 0x62);
  cipherspec += raw_string(0x04, 0x00, 0x80);
  cipherspec += raw_string(0x00, 0x00, 0x63);
  cipherspec += raw_string(0x00, 0x00, 0x03);
  cipherspec += raw_string(0x00, 0x00, 0x64);
  cipherspec += raw_string(0x02, 0x00, 0x80);

  if (!cspeclen) {
      cspeclen = strlen(cipherspec); 
      if (cspeclen <= 0xFF) cspeclen = raw_string(0x00, cspeclen);
      else cspeclen = raw_string(cspeclen / 256, cspeclen % 256);
  }

  if (!challenge) challenge = raw_string(0x4E, 0x45, 0x53, 0x53, 0x55, 0x53, 0x4E, 0x45, 0x53, 0x53, 0x55, 0x53, 0x4E, 0x45, 0x53, 0x53);    # NESSUS NESSUS NESS

  if (!challengelen) {
      challengelen = strlen(challenge);
      if (challengelen <= 0xFF) challengelen = raw_string(0x00, challengelen);
      else challengelen = raw_string(challengelen / 256, challengelen % 256);
  }

  mlen = raw_string(strlen(mtype) + strlen(version) + strlen(cspeclen) + strlen(sessionidlen) + strlen(challengelen) + strlen(cipherspec) + strlen(challenge) );

  intmsg = mtype + version + cspeclen + sessionidlen + challengelen + cipherspec + challenge;

  # the 0x80 is magic stuff
  myhello = raw_string(0x80, strlen(intmsg)) + intmsg;

  return(myhello);
}


function client_send_cert (contenttype, version, length, hshaketype, hlength, clength, clength2, certificate) {
  # contenttype = content type (1 byte) -- handshake is 0x16
  # version = version (2 bytes) -- SSL v3 is 0x03 0x00
  # length = length (2 bytes) of record following this length field
  # hshaketype = handshake type (1 byte) -- certificate is 0x0B
  
  # Note to self:  3 bytes is a *lot* of space...

  # hlength = handshake length (3 bytes) (also equal to length - 4)
  # clength = certificate length (3 bytes) (or hlength - 3)
  # clength2 = actual cert length (3 bytes) (just subtract another 3 from clength)
  # certificate = clength2 bytes of certificate
  

  if (!certificate) exit(0);                      # must have a cert... 

  certlen = strlen(certificate);

  if (!contenttype) contenttype = raw_string(0x16);
  if (!version) version = raw_string(0x03, 0x00);
  if (!hshaketype) hshaketype = raw_string(0x0B);

  if (!clength2) {
    clength2 = certlen; 
    if (clength2 <= 0xFF) clength2 = raw_string(0x00, 0x00, clength2);
    else clength2 = raw_string(0x00, clength2 / 256, clength2 % 256); 
  }

  if (!clength) {
      tlen = certlen + 3;
      if (tlen <= 0xFF) clength = raw_string(0x00, 0x00, tlen);
      else clength = raw_string(0x00, tlen / 256, tlen % 256); 
  }

  if (!hlength) {
      tlen = certlen + 6;
      if (certlen <= 0xFF) hlength = raw_string(0x00, 0x00, tlen);
      else hlength = raw_string(0x00, tlen / 256, tlen % 256);
  }

  if (!length) {
    length = certlen + 10;
    if (length <= 0xFF) length = raw_string(0x00, strlen(length));
    else length = raw_string(length / 256, length % 256);
  }

 
    
  client_cert = contenttype + version + length + hshaketype + hlength + clength + clength2 + certificate;
  return (client_cert); 
}
