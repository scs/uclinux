
/*
 *  Copyright (C) 2005 Sourcefire,Inc.
 */

#ifndef __XLINK2STATE_H__
#define __XLINK2STATE_H__

/* SMTP normally runs on port 25 */
#define SMTP_DEFAULT_SERVER_PORT  25


typedef struct _XLINK2STATE
{
    int length;
    int alerted;

} XLINK2STATE;

    

/*  Exported functions */
void XLINK2STATE_Init(void);
void XLINK2STATE_SessionFree(void *);
void XLINK2STATE_Free(void);
void SnortXLINK2STATE(Packet *p);
void XLINK2STATE_ParseArgs(u_char *args);


#endif  /* __XLINK2STATE_H__ */
