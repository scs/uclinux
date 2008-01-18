#ifndef _GETSINGLEPIC_H
#define _GETSINGLEPIC_H

#include "../../../../linux-2.6.x/drivers/media/video/blackfin/mt9v032.h"

extern int fd;
int getSinglePic(unsigned char *filename, int bgr);


#endif _GETSINGLEPIC_H


