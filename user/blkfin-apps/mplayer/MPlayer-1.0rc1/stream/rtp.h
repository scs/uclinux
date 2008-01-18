/* Imported from the dvbstream project
 *
 * Modified for use with MPlayer, for details see the changelog at
 * http://svn.mplayerhq.hu/mplayer/trunk/
 * $Id: rtp.h 19326 2006-08-04 19:38:59Z ben $
 */

#ifndef _RTP_H
#define _RTP_H

int read_rtp_from_server(int fd, char *buffer, int length);

#endif
