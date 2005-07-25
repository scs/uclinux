/*
*  $Id$
*
*   mpse.c
*    
*   An abstracted interface to the Multi-Pattern Matching routines,
*   thats why we're passing 'void *' objects around.
*
*   Copyright (C) 2002 SourceFire, Inc
*   Marc A Norton <mnorton@sourcefire.com>
*
**  
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "bitop.h"
#include "mwm.h"
#include "acsmx.h"
#include "acsmx2.h"
#include "sfksearch.h"
#include "mpse.h"  

static UINT64 s_bcnt=0;

typedef struct _mpse_struct {

  int    method;
  void * obj;

}MPSE;

void * mpseNew( int method )
{
   MPSE * p;

   p = (MPSE*)malloc( sizeof(MPSE) );
   if( !p ) return NULL;

   p->method=method;
   p->obj   =NULL;
   s_bcnt  =0;

   switch( method )
   {
     case MPSE_AUTO:
     case MPSE_MWM:
	p->obj = mwmNew();
        return (void*)p;
     break;
     case MPSE_AC:
       p->obj = acsmNew();
       return (void*)p;
     break;
     case MPSE_ACF:
       p->obj = acsmNew2();
       if(p->obj)acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_FULL  );
       return (void*)p;
     break;
     case MPSE_ACS:
       p->obj = acsmNew2();
       if(p->obj)acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_SPARSE  );
       return (void*)p;
     break;
     case MPSE_ACB:
       p->obj = acsmNew2();
       if(p->obj)acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_BANDED  );
       return (void*)p;
     break;
     case MPSE_ACSB:
       p->obj = acsmNew2();
       if(p->obj)acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_SPARSEBANDS  );
       return (void*)p;
     break;
     case MPSE_KTBM:
     case MPSE_LOWMEM:
	p->obj = KTrieNew();
       return (void*)p;
     break; 
     
     default:
       return 0;
     break; 
   }
}


void   mpseFree( void * pv )
{
  MPSE * p = (MPSE*)pv;
 
  switch( p->method )
   {
     case MPSE_AC:
       if(p->obj)acsmFree(p->obj);
       free(p);
       return ;
     break;
     case MPSE_ACF:
     case MPSE_ACS:
     case MPSE_ACB:
     case MPSE_ACSB:
       if(p->obj)acsmFree2(p->obj);
       free(p);
       return ;
     break;
     case MPSE_AUTO:
     case MPSE_MWM:
       if(p->obj)mwmFree( p->obj );
       free( p );
     break;
     case MPSE_KTBM:
     case MPSE_LOWMEM:
       return ;
     break;
     default:
       return ;
     break; 
   }
}

int  mpseAddPattern ( void * pv, void * P, int m, 
             unsigned noCase,unsigned offset, unsigned depth,  void* ID, int IID )
{
  MPSE * p = (MPSE*)pv;

  switch( p->method )
   {
     case MPSE_AC:
       return acsmAddPattern( (ACSM_STRUCT*)p->obj, (unsigned char *)P, m,
              noCase, offset, depth, ID, IID );
     break;
     case MPSE_ACF:
     case MPSE_ACS:
     case MPSE_ACB:
     case MPSE_ACSB:
       return acsmAddPattern2( (ACSM_STRUCT2*)p->obj, (unsigned char *)P, m,
              noCase, offset, depth, ID, IID );
     break;
     case MPSE_MWM:
       return mwmAddPatternEx( p->obj, (unsigned char *)P, m, 
              noCase, offset, depth, (void*)ID, IID );
     break;
     case MPSE_KTBM:
     case MPSE_LOWMEM:
       return KTrieAddPattern( (KTRIE_STRUCT *)p->obj, (unsigned char *)P, m, 
              noCase, ID );
     break; 
     default:
       return -1;
     break; 
   }
}

void mpseLargeShifts   ( void * pv, int flag )
{
  MPSE * p = (MPSE*)pv;
 
  switch( p->method )
   {
     case MPSE_AUTO:
     case MPSE_MWM:
       mwmLargeShifts( p->obj, flag );
     break; 
     
     default:
       return ;
     break; 
   }
}

int  mpsePrepPatterns  ( void * pv )
{
  MPSE * p = (MPSE*)pv;

  switch( p->method )
   {
     case MPSE_AC:
       return acsmCompile( (ACSM_STRUCT*) p->obj);
     break;
     case MPSE_ACF:
     case MPSE_ACS:
     case MPSE_ACB:
     case MPSE_ACSB:
       return acsmCompile2( (ACSM_STRUCT2*) p->obj);
     break;
     case MPSE_AUTO:
     case MPSE_MWM:
       return mwmPrepPatterns( p->obj );
     break;
     case MPSE_KTBM:
     case MPSE_LOWMEM:
       return KTrieCompile( (KTRIE_STRUCT *)p->obj);
     break; 
     
     default:
       return 1;
     break; 
   }
}

void mpseSetRuleMask ( void *pv, BITOP * rm )
{
  MPSE * p = (MPSE*)pv;

  switch( p->method )
   {
     case MPSE_AUTO:
     case MPSE_MWM:
       mwmSetRuleMask( p->obj, rm );
     break;
     
     default:
       return ;
     break; 
   }


}
int mpsePrintDetail( void *pv )
{
  MPSE * p = (MPSE*)pv;

  switch( p->method )
   {
     case MPSE_AC:
      return acsmPrintDetailInfo( (ACSM_STRUCT*) p->obj );
     break;
     case MPSE_ACF:
     case MPSE_ACS:
     case MPSE_ACB:
     case MPSE_ACSB:
      return acsmPrintDetailInfo2( (ACSM_STRUCT2*) p->obj );
      break;
     case MPSE_AUTO:
     case MPSE_MWM:
      return 0;
     break;
     case MPSE_LOWMEM:
       return 0;;
     break; 
     
     default:
       return 1;
     break; 
   }

 return 0;
}	


int mpsePrintSummary( )
{
   acsmPrintSummaryInfo();
   acsmPrintSummaryInfo2();
   return 0;
}	

int mpseSearch( void *pv, unsigned char * T, int n, 
    int ( *action )(void*id, int index, void *data), 
    void * data ) 
{
  MPSE * p = (MPSE*)pv;

  s_bcnt += n;
  
  switch( p->method )
   {
     case MPSE_AC:
      return acsmSearch( (ACSM_STRUCT*) p->obj, T, n, action, data );
     break;
     case MPSE_ACF:
     case MPSE_ACS:
     case MPSE_ACB:
     case MPSE_ACSB:
      return acsmSearch2( (ACSM_STRUCT2*) p->obj, T, n, action, data );
      break;
     case MPSE_AUTO:
     case MPSE_MWM:
      return mwmSearch( p->obj, T, n, action, data );
     break;
     case MPSE_LOWMEM:
       return  KTrieSearch( (KTRIE_STRUCT *)p->obj, T, n, action, data );
     break; 
     default:
       return 1;
     break; 
   }

}


UINT64 mpseGetPatByteCount( )
{
  return s_bcnt; 
}

void mpseResetByteCount( )
{
    s_bcnt = 0;
}

 
