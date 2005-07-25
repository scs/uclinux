
/*
 * Copyright (C) 2005 Sourcefire,Inc.
 */

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <rpc/types.h>

#include "str_search.h"
#include "mpse.h"

typedef struct tag_search
{
    void *mpse;
    unsigned int max_len;
} t_search;

static t_search *_mpse = NULL;
static unsigned int  _num_mpse;

int SearchInit(unsigned int num)
{
    unsigned int i;

    _num_mpse = num;

    _mpse = malloc(sizeof(t_search) * num);
    if ( _mpse == NULL )
        return -1;

    for ( i = 0; i < num; i++ )
    {
        _mpse[i].mpse = mpseNew(MPSE_AC);
        _mpse[i].max_len = 0;
    }
    return 0;
}

void SearchFree()
{
    unsigned int i;

    if ( _mpse != NULL )
    {
        for ( i = 0; i < _num_mpse; i++ )
        {
            if ( _mpse[i].mpse != NULL )
                mpseFree(_mpse[i].mpse);
        }
        free(_mpse);
    }
}


/*  Do efficient search of data */
int SearchFindString(unsigned int mpse_id, char *str, int str_len, int (*Match) (void *, int, void *))
{
    int num;

    if ( str_len == 0 )
        str_len = _mpse[mpse_id].max_len;
    num = mpseSearch(_mpse[mpse_id].mpse, str, str_len, Match, (void *) str);
    
    return num;
}


void SearchAdd(unsigned int mpse_id, char *pat, int id)
{
    unsigned int len = strlen(pat);

    mpseAddPattern(_mpse[mpse_id].mpse, pat, len, 1, 0, 0, (void *) id, 0);

    if ( len > _mpse[mpse_id].max_len )
        _mpse[mpse_id].max_len = len;
}

void SearchPrepPatterns(unsigned int mpse_id)
{
    mpsePrepPatterns(_mpse[mpse_id].mpse);
}
