/*
 *
 *  Stream SBC files over RFCOMM
 *
 *  Copyright (C) 2004  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

struct sbc_frame_hdr {
	uint8_t syncword:8;		/* Sync word */
	uint8_t subbands:1;		/* Subbands */
	uint8_t allocation_method:1;	/* Allocation method */
	uint8_t channel_mode:2;		/* Channel mode */
	uint8_t blocks:2;		/* Blocks */
	uint8_t sampling_frequency:2;	/* Sampling frequency */
	uint8_t bitpool:8;		/* Bitpool */
	uint8_t crc_check:8;		/* CRC check */
} __attribute__ ((packed));

static int get_channel(bdaddr_t *src, bdaddr_t *dst, uint8_t *channel)
{
	sdp_session_t *s;
	sdp_list_t *class, *attrs, *rsp;
	uuid_t svclass;
	uint16_t attr1, attr2;
	int err;

	s = sdp_connect(src, dst, 0);
	if (!s)
		return -1;

	sdp_uuid16_create(&svclass, SERIAL_PORT_SVCLASS_ID);
	class = sdp_list_append(NULL, &svclass);

	attr1 = SDP_ATTR_PROTO_DESC_LIST;
	attr2 = SDP_ATTR_SVCNAME_PRIMARY;
	attrs = sdp_list_append(NULL, &attr1);
	attrs = sdp_list_append(attrs, &attr2);

	err = sdp_service_search_attr_req(s, class,
				SDP_ATTR_REQ_INDIVIDUAL, attrs, &rsp);

	sdp_close(s);

	if (err)
		return -1;

	for(; rsp; rsp = rsp->next) {
		sdp_record_t *rec = (sdp_record_t *) rsp->data;
		sdp_list_t *protos;

		if (!sdp_get_access_protos(rec, &protos)) {
			uint8_t val = sdp_get_proto_port(protos, RFCOMM_UUID);
			if (val > 0) {
				*channel = val;
				return 0;
			}
		}
	}

	return -1;
}

static int rfcomm_connect(bdaddr_t *src, bdaddr_t *dst, uint8_t channel)
{
	struct sockaddr_rc addr;
	int sk;

	sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, src);
	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, dst);
	addr.rc_channel = channel;
	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return -1;
	}

	return sk;
}

static int calc_frame_len(struct sbc_frame_hdr *hdr)
{
	int tmp, nrof_subbands, nrof_blocks;

	nrof_subbands = (hdr->subbands + 1) * 4;
	nrof_blocks = (hdr->blocks + 1) * 4;

	switch (hdr->channel_mode) {
	case 0x00:
		nrof_subbands /= 2;
		tmp = nrof_blocks * hdr->bitpool;
		break;
	case 0x01:
		tmp = nrof_blocks * hdr->bitpool * 2;
		break;
	case 0x02:
		tmp = nrof_blocks * hdr->bitpool;
		break;
	case 0x03:
		tmp = nrof_blocks * hdr->bitpool + nrof_subbands;
		break;
	default:
		return 0;
	}

	return (nrof_subbands + ((tmp + 7) / 8));
}

static ssize_t __read(int fd, void *buf, size_t count)
{
	ssize_t len, pos = 0;

	while (count > 0) {
		len = read(fd, buf + pos, count);
		if (len <= 0)
			return len;

		count -= len;
		pos   += len;
	}

	return pos;
}

static ssize_t __write(int fd, const void *buf, size_t count)
{
	ssize_t len, pos = 0;

	while (count > 0) {
		len = write(fd, buf + pos, count);
		if (len <= 0)
			return len;

		count -= len;
		pos   += len;
	}

	return pos;
}

static int stream_sbc(fd, sk)
{
	struct sbc_frame_hdr hdr;
	unsigned char buf[330];
	int err, len, size, pos = 0;

	while (1) {
		len = __read(fd, &hdr, sizeof(hdr));
		if (len < 0) {
			fprintf(stderr, "Unable to read frame header (error %d)\n", errno);
			break;
		}

		if (len == 0)
			break;

		if (len < sizeof(hdr) || hdr.syncword != 0x9c) {
			fprintf(stderr, "Corrupted SBC stream (len %d syncword 0x%02x)\n",
					len, hdr.syncword);
			break;
		}

		size = calc_frame_len(&hdr);
		if (size > sizeof(buf) - sizeof(hdr)) {
			fprintf(stderr, "Frame size larger than buffer (size %d)\n",
					size + sizeof(hdr));
			break;
		}

		if (sizeof(buf) - pos < sizeof(hdr) + size) {
			err = __write(sk, buf, pos);
			if (err < 0) {
				fprintf(stderr, "Unable to send SBC stream (error %d)\n", errno);
				break;
			}

			pos = 0;
		}

		memcpy(buf + pos, &hdr, sizeof(hdr));
		len = __read(fd, buf + pos + sizeof(hdr), size);
		if (len < 0) {
			fprintf(stderr, "Unable to read frame data (error %d)\n", errno);
			break;
		}

		if (len < size) {
			fprintf(stderr, "Corrupted SBC data (len %d)\n", len);
			break;
		}

		pos += sizeof(hdr) + size;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	bdaddr_t bdaddr;
	uint8_t channel;
	int sk, fd = fileno(stdin);

	if (argc < 2) {
		fprintf(stderr, "Usage: rcplay <bdaddr> [filename]\n");
		exit(1);
	}

	str2ba(argv[1], &bdaddr);

	if (argc > 2 && strcmp(argv[2], "-")) {
		fd = open(argv[2], O_RDONLY);
		if (fd < 0) {
			perror("Can't open file");
			exit(1);
		}
	}

	if (get_channel(BDADDR_ANY, &bdaddr, &channel) < 0) {
		perror("Can't get channel number");
		close(fd);
		exit(1);
	}

	sk = rfcomm_connect(BDADDR_ANY, &bdaddr, channel);
	if (sk < 0) {
		perror("Can't open connection");
		close(fd);
		exit(1);
	}

	stream_sbc(fd, sk);

	close(sk);

	if (fd > fileno(stderr))
		close(fd);

	return 0;
}
