/*
 * File:         ringbuffer.c 
 * Description:  simple circular fifo of uint16's
 *               suitable for inclusion or compile with
 *               cc -DTEST_RINGBUFFER ringbuffer.c -o ringtest; ./ringtest 
 *
 * Rev:          $Id$
 * Created:      Tue Dec  9 16:27:09 CET 2003
 * Author:       Luuk van Dijk
 * mail:         lvd@buyways.nl
 * 
 * Copyright (C) 2003 Luuk van Dijk, BuyWays B.V.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


#include <linux/types.h>

#ifdef __KERNEL__
#define malloc(x) kmalloc((x),GFP_KERNEL)
#define free(x) kfree(x)
#else
#include <stdlib.h>
#endif


struct ringbuffer {
  int   size;            /* set at initialization */
  int   head_w;          /* postincrement, updated by writer */
  int   tail_r;          /* postincrement, updated by reader */
  int   overflow_count;  /* updated by writer */
  int   underflow_count; /* updated by reader */
  int   pad[3];          /* align data at 8*sizeof(int) */
  uint16_t   data[0];
};


// size: number of uint16_t's in the data
struct ringbuffer* ringbuffer_init(int size){

  struct ringbuffer* rb = 
    malloc( sizeof(struct ringbuffer) + size*sizeof(uint16_t) );

  if( !rb ) return NULL;
  
  rb->size = size;
  rb->head_w = rb->tail_r = 0;
  rb->overflow_count = rb->underflow_count = 0;

  return rb;

}

void ringbuffer_done(struct ringbuffer* rb){ free(rb); }

int ringbuffer_used(struct ringbuffer* rb){ 
  int f = rb->head_w - rb->tail_r; 
  if( f<0 ) f += rb->size; 
  return f;
}

int ringbuffer_would_underflow(struct ringbuffer* rb, uint16_t toread){ return (ringbuffer_used(rb) - toread)  < 0; }
int ringbuffer_would_overflow(struct ringbuffer* rb, uint16_t towrite){ return (ringbuffer_used(rb) + towrite) >= rb->size; }


int ringbuffer_write_head(struct ringbuffer* rb, uint16_t* data, int count){

  int cnt = count;

  if( ringbuffer_would_overflow(rb, count) ){
    ++(rb->overflow_count);
    return -1;
  }

  if( (rb->head_w + count) >= rb->size ){
    count = rb->size - rb->head_w;
    if(count)
      memmove( rb->data+rb->head_w, data, count*sizeof(uint16_t) );
    rb->head_w = 0;
    data += count;
    count = cnt-count;
  }
  
  if( count ){
    memmove( rb->data+rb->head_w, data, count*sizeof(uint16_t) );
    rb->head_w += count;
  }

  return cnt;

}

int ringbuffer_read_tail(struct ringbuffer* rb, uint16_t* data, int count){

  int cnt = count;

  if( ringbuffer_would_underflow(rb, count) ){
    ++(rb->underflow_count);
    return -1;
  }

  if( (rb->tail_r + count) >= rb->size ){
    count = rb->size - rb->tail_r;
    if(count)
      memmove( data, rb->data+rb->tail_r, count*sizeof(uint16_t) );
    rb->tail_r = 0;
    data += count;
    count = cnt-count;
  }

  if( count ){
    memmove( data, rb->data+rb->tail_r, count*sizeof(uint16_t) );
    rb->tail_r += count;
  }
  
  return cnt;
}


/************************************************************/

#ifdef __KERNEL__

// POTENTIAL BUG: if these fail with EFAULT the number of consumed bytes is undefined!

int ringbuffer_write_head_from_user(struct ringbuffer* rb, uint16_t* data, int count){
  
  int cnt = count;
  
  if( ringbuffer_would_overflow(rb, count) ){
    ++(rb->overflow_count);
    return -EAGAIN;
  }

  if( (rb->head_w + count) >= rb->size ){
    count = rb->size - rb->head_w;
    if(count)
      if( copy_from_user( rb->data+rb->head_w, data, count*sizeof(uint16_t) ) )
	return -EFAULT;
    rb->head_w = 0;
    data += count;
    count = cnt-count;
  }
  
  if( count ){
    if( copy_from_user( rb->data+rb->head_w, data, count*sizeof(uint16_t) ) )
      return -EFAULT;
    rb->head_w += count;
  }
  
  return cnt;
  
}



int ringbuffer_read_tail_to_user(struct ringbuffer* rb, uint16_t* data, int count){

  int cnt = count;

  if( ringbuffer_would_underflow(rb, count) ){
    ++(rb->underflow_count);
    return -EAGAIN;
  }

  if( (rb->tail_r + count) >= rb->size ){
    count = rb->size - rb->tail_r;
    if(count)
      if (copy_to_user( data, rb->data+rb->tail_r, count*sizeof(uint16_t) ) )
	return -EFAULT;

    rb->tail_r = 0;
    data += count;
    count = cnt-count;
  }

  if( count ){
    if (copy_to_user( data, rb->data+rb->tail_r, count*sizeof(uint16_t) ) )
      return -EFAULT;
    rb->tail_r += count;
  }
  
  return cnt;
}


#endif



/*************************************************************/


#ifdef TEST_RINGBUFFER

#ifdef __KERNEL__
#error "Can't test in __KERNEL__"
#endif

#include <assert.h>

int main(int argc, char* argv[]){

  int i;

  uint16_t data_in[] = { 0x0000, 0x0001, 0x0002, 0x0003 };
  uint16_t data_out[4];

  struct ringbuffer* rb = ringbuffer_init(16);
  
  assert( !ringbuffer_would_underflow(rb,0) );
  assert(  ringbuffer_would_underflow(rb,1) );

  assert( !ringbuffer_would_overflow(rb,0) );
  assert( !ringbuffer_would_overflow(rb,1) );

  assert( !ringbuffer_would_overflow(rb,15) );
  assert(  ringbuffer_would_overflow(rb,16) );
  assert(  ringbuffer_would_overflow(rb,17) );
  
  assert( 2 == ringbuffer_write_head(rb, data_in, 2) );

  assert( !ringbuffer_would_underflow(rb,0) );
  assert( !ringbuffer_would_underflow(rb,1) );
  assert( !ringbuffer_would_underflow(rb,2) );
  assert(  ringbuffer_would_underflow(rb,3) );
  
  assert( !ringbuffer_would_overflow(rb,13) );
  assert(  ringbuffer_would_overflow(rb,14) );
  assert(  ringbuffer_would_overflow(rb,15) );
  
  assert( -1 == ringbuffer_write_head(rb, data_in, 20) );
  assert( 2 == ringbuffer_used(rb) );

  assert( 2 == ringbuffer_read_tail(rb, data_out, 2) );
  assert( data_in[0] == data_out[0] );
  assert( data_in[1] == data_out[1] );

  assert( 0 == ringbuffer_used(rb) );

  assert( 2 == ringbuffer_write_head(rb, data_in, 2) );
  assert( 4 == ringbuffer_write_head(rb, data_in, 4) );
  assert( 4 == ringbuffer_write_head(rb, data_in, 4) );
  assert( 4 == ringbuffer_write_head(rb, data_in, 4) );
  assert( -1 == ringbuffer_write_head(rb, data_in, 4) );

  assert( 14 == ringbuffer_used(rb) );

  assert( 2 == ringbuffer_read_tail(rb, data_out, 2) );
  assert( data_in[0] == data_out[0] );
  assert( data_in[1] == data_out[1] );


  assert( 3 == ringbuffer_write_head(rb, data_in, 3) );

  assert( 15 == ringbuffer_used(rb) );

  assert( !ringbuffer_would_overflow(rb,0) );
  assert(  ringbuffer_would_overflow(rb,1) );

  assert( !ringbuffer_would_underflow(rb,15) );
  assert(  ringbuffer_would_underflow(rb,16) );
  assert(  ringbuffer_would_underflow(rb,17) );

  assert( 4 == ringbuffer_read_tail(rb, data_out, 4) );
  assert( data_in[0] == data_out[0] );
  assert( data_in[1] == data_out[1] );
  assert( data_in[2] == data_out[2] );
  assert( data_in[3] == data_out[3] );

  assert( 4 == ringbuffer_read_tail(rb, data_out, 4) );
  assert( data_in[0] == data_out[0] );
  assert( data_in[1] == data_out[1] );
  assert( data_in[2] == data_out[2] );
  assert( data_in[3] == data_out[3] );

  assert( 4 == ringbuffer_read_tail(rb, data_out, 4) );
  assert( data_in[0] == data_out[0] );
  assert( data_in[1] == data_out[1] );
  assert( data_in[2] == data_out[2] );
  assert( data_in[3] == data_out[3] );

  assert( 3 == ringbuffer_used(rb) );

  assert( -1 == ringbuffer_read_tail(rb, data_out, 4) );
  assert( 3 == ringbuffer_read_tail(rb, data_out+1, 3) );
  assert( data_in[0] == data_out[1] );
  assert( data_in[1] == data_out[2] );
  assert( data_in[2] == data_out[3] );

  assert( 0 == ringbuffer_used(rb) );

  assert( 4 == ringbuffer_write_head(rb, data_in, 4) );
  assert( 2 == ringbuffer_write_head(rb, data_in, 2) );

  // 7 behind...

  for(i=0; i<2000;++i){

    int j = i - 1;

    uint16_t in[6] =  { i, i*2, i*4, i*8, i*10, i*13 };
    uint16_t in7[6] = { j, j*2, j*4, j*8, j*10, j*13 };
    uint16_t out[6];

    assert( 6 == ringbuffer_used(rb) );

    assert( 6 == ringbuffer_write_head(rb, in, 6) );
    assert( 6 == ringbuffer_read_tail(rb, out, 6) );
    
    if( i>1 )
      for( j=0; j<6; ++j )
	assert( out[j] == in7[j] );
    // printf(".");

  }

  ringbuffer_done(rb);
  
  printf("if we didn't crash everything tested ok.\n");
  
  return 0;
}

#endif
