
/*
 *  Copyright (C) 2005 Sourcefire,Inc.
 */
#ifndef __SMTP_SEARCH_H__
#define __SMTP_SEARCH_H__

/* Function prototypes  */
int  SearchInit(unsigned int num);
void SearchFree();
void SearchAdd(unsigned int mpse_id, char *pat, int id);
void SearchPrepPatterns(unsigned int mpse_id);
int  SearchFindString(unsigned int mpse_id, char *str, int str_len, int (*Match) (void *, int, void *));


#endif  /*  __SMTP_SEARCH_H__  */

