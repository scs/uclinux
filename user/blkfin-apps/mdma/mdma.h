/*
 * File:         mdma.h
 * Based on:
 * Author:       Marc Hoffman
 *
 * Created:      11/15/2007
 * Description:  Blackfin 2D DMA engine interface code user level API.
 *
 * Modified:
 *               Copyright 2004-2007 Analog Devices Inc.
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
#ifndef _MDMA_H
#define _MDMA_H

typedef unsigned short uword;

typedef struct {
  uword sal;
  uword sah;
  uword cfg;
  uword xc;
  uword xm;
  uword yc;
  uword ym;
} dmadsc_t;


typedef struct dmactrl_block {
  unsigned sem;
  int      maxmoves;
  dmadsc_t *src;
  dmadsc_t *dst;
  unsigned control;
  dmadsc_t *psrc;
  dmadsc_t *pdst;
  int       n;     /* require 32 byte alignment for cache line flushing */
  dmadsc_t desc[1];
} bfdmactrl_t;


/* Low Level DMA Kick Off */
#define bfin_dodma(sin,din,sdcfg) \
   asm volatile  ("excpt 0xd;\n\t" : : "q0" (sin), "q1" (din), "q2" (sdcfg))


/* Low Level Coherence Utilities. */
#define FLUSH(x)      asm ("flush [%0];\n\t" : : "a" (x))

#define INVALIDATE(x) ({ unsigned _v; \
  asm volatile ("flushinv [%1]; %0=[%1];\n\t" : "=d" (_v) : "a" (x)); _v; })

static inline void sync_write32 (unsigned *addr, unsigned val)
{
  *addr=val;
  FLUSH(addr);
}

static inline void update_target (dmadsc_t *p, unsigned val)
{
  p->sal=val;
  p->sah=val>>16;
  FLUSH(p);
}

static inline void *get_pointer (dmadsc_t *p)
{
  return (void *)((p->sah<<16)|p->sal);
}

static inline unsigned sync_read32 (unsigned *addr)
{
  return INVALIDATE(addr);
}


extern bfdmactrl_t *alloc_dmactrl (int nmax);
extern void bfmdma_reset_chain (bfdmactrl_t *dmas);

extern void dma_add_block_move (bfdmactrl_t *dmac, int ws,
				unsigned *dsta, int dw, int dh, int ds,
				unsigned *srca, int sw, int sh, int ss);

extern void dma_add_move (bfdmactrl_t *dmac, unsigned *dsta, unsigned *srca, int n);

extern void dma_add_stop_flag (bfdmactrl_t *dmac);
extern void dma_print (bfdmactrl_t *dmac);

extern unsigned  bfmdma (bfdmactrl_t *dmac);

extern unsigned dma_wait (unsigned flag);

extern unsigned bfdma_wait (bfdmactrl_t *dmac);

#endif
