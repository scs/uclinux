/*
 * File:         sound/blackfin/ac97_sport.c
 * Based on:
 * Author:       Luuk van Dijk, Bas Vermeulen <blackfin@buyways.nl>
 *
 * Created:      Sat Dec  6 21:40:06 CET 2003
 * Description:  low level driver for ac97 connected to sportX/dmaY on blackfin 53x
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright (C) 2003 Luuk van Dijk, Bas Vermeulen BuyWays B.V.
 *               Copyright 2003-2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see the file COPYING, or write
 * to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __AC97_SPORT_H__
#define __AC97_SPORT_H__

/*
 * SYNOPSIS:
 *
 *  static struct ac97_sport_dev_t* dev=NULL;
 *
 *  // install a handler before opening the device!
 *  void ivg9handler(void){ if(dev) ac97_sport_handle_irq(dev); }
 *
 *  install_interrupt_handler( IVG9, ivghandler );
 *   NOTE: this must enable the interrupt in the IMASK /and/ the SIC_IMASK
 *
 *
 *  dev = ac97_sport_open(bufsize);
 *  ac97_sport_start|stop(dev);
 *  ac97_sport_close(dev);
 *
 *  void ac97_sport_set_talktrough_mode(struct ac97_sport_dev_t* dev);
 *  set to talktrougth testing mode: rxbuf = txbuf, and init mixer
 *
 *  int    result = ac97_sport_set_register(dev, int register, uint16_t value);
 *  int    value  = ac97_sport_get_register(dev, int register);
 *
 *  //  negative get value means register cache is (still) dirty
 *
 *  int result = ac97_sport_put_pcm_from_user(dev, uint16_t* pcmdata, size_t len)
 *  int result = ac97_sport_get_pcm_to_user( dev, uint16_t* pcmdata, size_t len)
 *
 *  result = 0 (ok), EAGAIN or copy_to/from_user result code
 *
 *
 */

/*
 * since we can have only 1 device in the b533 I removed the dev argument
 * and made it a static variable in ac97_sport.c
 * -- lvd 2004/01/09
 */

// struct ac97_sport_dev_t;

// bufsize: in units of ac97 frames
int ac97_sport_open(size_t bufsize, size_t fragsize);

void ac97_sport_set_talkthrough_mode(void);

void ac97_sport_close(void);

// interrupt handlers
int ac97_sport_handle_rx(void);
int ac97_sport_handle_tx(void);

// these functions return -EAGAIN if the cmdfifo is full or the cache is still dirty
// and -EINVAL if reg not even and between 0 and 127
// 0 means ok.

int ac97_sport_set_register(int reg, uint16_t val);

int ac97_sport_get_register(int reg, uint16_t * pval);

//ssize_t ac97_sport_put_pcm_from_user(uint32_t* pcmdata, size_t len);
//ssize_t ac97_sport_get_pcm_to_user(  uint32_t* pcmdata, size_t len);
ssize_t ac97_audio_write(const uint8_t * pcmdata, size_t len);
ssize_t ac97_audio_read(uint8_t * pcmdata, size_t len);

ssize_t ac97_audio_read_min_bytes(void);
ssize_t ac97_audio_write_max_bytes(void);

int ac97_wait_for_audio_read_with_timeout(unsigned long timeout);
int ac97_wait_for_audio_write_with_timeout(unsigned long timeout);

int ac97_get_channels(void);
void ac97_set_channels(int channels);

wait_queue_head_t *ac97_get_read_waitqueue(void);
wait_queue_head_t *ac97_get_write_waitqueue(void);

void ac97_sport_silence(void);

void ac97_sport_start(void);
void ac97_sport_stop(void);

#endif
